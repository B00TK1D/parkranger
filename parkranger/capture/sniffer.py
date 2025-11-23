import threading
import time
import socket
from typing import Optional, Callable
from dataclasses import dataclass, field

# Configure scapy before importing to avoid IPv6 issues
import os
os.environ["SCAPY_USE_LIBPCAP"] = "0"

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.config import conf as scapy_conf
scapy_conf.ipv6_enabled = False

from scapy.sendrecv import sniff
from scapy.layers.inet import IP, TCP

from .rtt import RTTTracker
from ..config import config


@dataclass
class Connection:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packets: int = 0
    bytes_transferred: int = 0
    state: str = "unknown"

    @property
    def key(self) -> tuple:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port)

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "packets": self.packets,
            "bytes_transferred": self.bytes_transferred,
            "state": self.state,
            "duration": self.last_seen - self.first_seen,
        }


class PacketSniffer:
    def __init__(self, rtt_tracker: RTTTracker, interface: Optional[str] = None, port_filter: Optional[list[int]] = None):
        self.rtt_tracker = rtt_tracker
        self.interface = interface or config.interface
        self.port_filter = port_filter or config.port_filter
        self._connections: dict[tuple, Connection] = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: list[Callable] = []
        self._local_ips: set[str] = set()
        self._detect_local_ips()

    def _detect_local_ips(self) -> None:
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            self._local_ips.add(local_ip)
        except Exception:
            pass
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self._local_ips.add(s.getsockname()[0])
            s.close()
        except Exception:
            pass
        self._local_ips.add("127.0.0.1")
        self._local_ips.add("::1")

    def _is_local_ip(self, ip: str) -> bool:
        if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
            return True
        if ip.startswith("172."):
            try:
                second_octet = int(ip.split(".")[1])
                if 16 <= second_octet <= 31:
                    return True
            except (ValueError, IndexError):
                pass
        return ip in self._local_ips

    def add_callback(self, callback: Callable) -> None:
        self._callbacks.append(callback)

    def _notify_callbacks(self, event_type: str, data: dict) -> None:
        for callback in self._callbacks:
            try:
                callback(event_type, data)
            except Exception:
                pass

    def _build_filter(self) -> str:
        if not self.port_filter:
            return "tcp"
        port_conditions = " or ".join(f"port {p}" for p in self.port_filter)
        return f"tcp and ({port_conditions})"

    def _process_packet(self, packet) -> None:
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        flags = tcp_layer.flags

        # Determine remote IP (the one we care about)
        if self._is_local_ip(src_ip) and not self._is_local_ip(dst_ip):
            remote_ip = dst_ip
            is_outgoing = True
        elif self._is_local_ip(dst_ip) and not self._is_local_ip(src_ip):
            remote_ip = src_ip
            is_outgoing = False
        else:
            return  # Skip local-to-local or remote-to-remote

        conn_key = (min(src_ip, dst_ip), min(src_port, dst_port), max(src_ip, dst_ip), max(src_port, dst_port))

        with self._lock:
            if conn_key not in self._connections:
                if not is_outgoing:  # Incoming connection
                    self._connections[conn_key] = Connection(
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                    )
                else:
                    self._connections[conn_key] = Connection(
                        src_ip=dst_ip,
                        src_port=dst_port,
                        dst_ip=src_ip,
                        dst_port=src_port,
                    )

            conn = self._connections[conn_key]
            conn.last_seen = time.time()
            conn.packets += 1
            conn.bytes_transferred += len(packet)

        # Track TCP handshake for RTT
        if flags & 0x02 and not (flags & 0x10):  # SYN only
            self.rtt_tracker.record_syn(src_ip, src_port, dst_ip, dst_port)
            conn.state = "syn_sent"

        elif flags & 0x02 and flags & 0x10:  # SYN-ACK
            rtt = self.rtt_tracker.record_syn_ack(src_ip, src_port, dst_ip, dst_port)
            conn.state = "syn_ack_received"
            if rtt is not None:
                self._notify_callbacks("rtt_update", {
                    "ip": src_ip,
                    "tcp_rtt": rtt,
                    "connection": conn.to_dict(),
                })

        elif flags & 0x10:  # ACK
            if conn.state == "syn_ack_received":
                conn.state = "established"

            # Track data ACKs for ongoing RTT measurement
            if tcp_layer.ack:
                rtt = self.rtt_tracker.record_ack(src_ip, src_port, dst_ip, dst_port, tcp_layer.ack)
                if rtt is not None:
                    self._notify_callbacks("rtt_update", {
                        "ip": remote_ip,
                        "tcp_rtt": rtt,
                    })

        # Track outgoing data for RTT measurement
        if is_outgoing and len(tcp_layer.payload) > 0:
            self.rtt_tracker.record_data_sent(src_ip, src_port, dst_ip, dst_port, tcp_layer.seq)

        if flags & 0x01 or flags & 0x04:  # FIN or RST
            conn.state = "closed"

    def _sniff_loop(self) -> None:
        try:
            sniff(
                iface=self.interface,
                filter=self._build_filter(),
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            print(f"Sniffer error: {e}")
            self._running = False

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    def get_connections(self, active_only: bool = True, max_age: float = None) -> list[Connection]:
        max_age = max_age or config.connection_timeout
        now = time.time()
        with self._lock:
            connections = list(self._connections.values())

        if active_only:
            connections = [c for c in connections if now - c.last_seen < max_age]

        return sorted(connections, key=lambda c: c.last_seen, reverse=True)

    def get_unique_remote_ips(self) -> set[str]:
        connections = self.get_connections()
        ips = set()
        for conn in connections:
            if not self._is_local_ip(conn.src_ip):
                ips.add(conn.src_ip)
            if not self._is_local_ip(conn.dst_ip):
                ips.add(conn.dst_ip)
        return ips

    def cleanup_old_connections(self) -> int:
        now = time.time()
        max_age = config.connection_timeout
        with self._lock:
            old_keys = [k for k, v in self._connections.items() if now - v.last_seen > max_age]
            for k in old_keys:
                del self._connections[k]
            return len(old_keys)
