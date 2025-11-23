import time
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

from ..config import config


@dataclass
class RTTMeasurement:
    tcp_rtt_samples: list[float] = field(default_factory=list)
    icmp_rtt_samples: list[float] = field(default_factory=list)
    last_updated: float = field(default_factory=time.time)

    @property
    def tcp_rtt(self) -> Optional[float]:
        if not self.tcp_rtt_samples:
            return None
        return min(self.tcp_rtt_samples)  # Use minimum as best estimate

    @property
    def icmp_rtt(self) -> Optional[float]:
        if not self.icmp_rtt_samples:
            return None
        return min(self.icmp_rtt_samples)

    @property
    def rtt_difference(self) -> Optional[float]:
        if self.tcp_rtt is None or self.icmp_rtt is None:
            return None
        diff = self.tcp_rtt - self.icmp_rtt
        return max(0, diff)  # Can't be negative in theory

    def add_tcp_sample(self, rtt_ms: float) -> None:
        self.tcp_rtt_samples.append(rtt_ms)
        if len(self.tcp_rtt_samples) > 100:
            self.tcp_rtt_samples = self.tcp_rtt_samples[-100:]
        self.last_updated = time.time()

    def add_icmp_sample(self, rtt_ms: float) -> None:
        self.icmp_rtt_samples.append(rtt_ms)
        if len(self.icmp_rtt_samples) > 20:
            self.icmp_rtt_samples = self.icmp_rtt_samples[-20:]
        self.last_updated = time.time()


class RTTTracker:
    """
    Tracks RTT measurements for IP addresses.

    TCP RTT is measured only during the initial handshake (SYN -> SYN-ACK)
    to get accurate network latency without application processing delays.
    """

    def __init__(self):
        self._measurements: dict[str, RTTMeasurement] = defaultdict(RTTMeasurement)
        self._pending_syns: dict[tuple[str, int, str, int], float] = {}
        self._lock = threading.Lock()
        self._ping_cache: dict[str, float] = {}
        self._ping_cache_time: dict[str, float] = {}

    def record_syn(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> None:
        """Record when a SYN packet is sent to start RTT measurement."""
        key = (src_ip, src_port, dst_ip, dst_port)
        with self._lock:
            self._pending_syns[key] = time.time()

    def record_syn_ack(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Optional[float]:
        """Record when SYN-ACK is received and calculate RTT from the initial handshake."""
        key = (dst_ip, dst_port, src_ip, src_port)  # Reversed for response
        with self._lock:
            if key in self._pending_syns:
                syn_time = self._pending_syns.pop(key)
                rtt_ms = (time.time() - syn_time) * 1000
                self._measurements[src_ip].add_tcp_sample(rtt_ms)
                return rtt_ms
        return None

    def get_measurement(self, ip: str) -> RTTMeasurement:
        with self._lock:
            return self._measurements[ip]

    def get_all_measurements(self) -> dict[str, RTTMeasurement]:
        with self._lock:
            return dict(self._measurements)

    def ping_ip(self, ip: str, force: bool = False) -> Optional[float]:
        cache_ttl = 60.0
        now = time.time()

        with self._lock:
            if not force and ip in self._ping_cache:
                if now - self._ping_cache_time.get(ip, 0) < cache_ttl:
                    return self._ping_cache[ip]

        try:
            result = subprocess.run(
                ["ping", "-c", str(config.ping_count), "-W", str(int(config.ping_timeout)), ip],
                capture_output=True,
                text=True,
                timeout=config.ping_timeout * config.ping_count + 2
            )

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "min/avg/max" in line:
                        parts = line.split("=")[-1].strip().split("/")
                        min_rtt = float(parts[0])

                        with self._lock:
                            self._measurements[ip].add_icmp_sample(min_rtt)
                            self._ping_cache[ip] = min_rtt
                            self._ping_cache_time[ip] = now
                        return min_rtt
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError, IndexError):
            pass

        return None

    def cleanup_stale(self, max_age: float = 30.0) -> None:
        """Clean up pending SYN packets that never received a response."""
        now = time.time()
        with self._lock:
            stale_syns = [k for k, v in self._pending_syns.items() if now - v > max_age]
            for k in stale_syns:
                del self._pending_syns[k]
