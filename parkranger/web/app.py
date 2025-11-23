import netifaces
import os
import socket
import time
from queue import Queue, Empty
from typing import Optional

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

from ..capture.sniffer import PacketSniffer
from ..capture.rtt import RTTTracker
from ..geo.location import GeoLocator
from ..geo.cities import CityFinder
from ..analysis.fingerprint import VPNFingerprinter
from ..config import config
from ..db import get_database, Database


socketio = SocketIO(cors_allowed_origins="*", async_mode="eventlet")

rtt_tracker: RTTTracker = None
sniffer: PacketSniffer = None
geolocator: GeoLocator = None
city_finder: CityFinder = None
fingerprinter: VPNFingerprinter = None
event_queue: Queue = None  # Queue for cross-thread event passing
database: Database = None
local_ips: set[str] = set()  # Server's own IP addresses to ignore
last_refresh_time: dict[str, float] = {}  # Rate limiting for refreshes
registered_real_ips: set[str] = set()  # Real client IPs behind proxies to analyze


def get_local_ips() -> set[str]:
    """Get all IP addresses assigned to local network interfaces."""
    ips = {"127.0.0.1", "::1", "localhost"}
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            # IPv4
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if "addr" in addr:
                        ips.add(addr["addr"])
            # IPv6
            if netifaces.AF_INET6 in addrs:
                for addr in addrs[netifaces.AF_INET6]:
                    if "addr" in addr:
                        # Remove scope ID from IPv6 addresses
                        ip = addr["addr"].split("%")[0]
                        ips.add(ip)
    except Exception:
        pass
    return ips


def is_local_ip(ip: str) -> bool:
    """Check if an IP is a local/server IP that should be ignored."""
    if ip in local_ips:
        return True
    # Also check for localhost patterns
    if ip.startswith("127.") or ip == "::1":
        return True
    return False


def can_refresh_ip(ip: str, min_interval: float = 1.0) -> bool:
    """Check if enough time has passed since last refresh for this IP."""
    now = time.time()
    last_time = last_refresh_time.get(ip, 0)
    if now - last_time >= min_interval:
        last_refresh_time[ip] = now
        return True
    return False


def get_visitor_ip() -> str:
    """Get the real IP of the visitor, respecting X-Forwarded-For headers."""
    # Check X-Forwarded-For header first (for proxies/load balancers)
    # Try multiple common header variations and check environ directly for WebSocket
    forwarded_for = (
        request.headers.get("X-Forwarded-For") or
        request.headers.get("X-FORWARDED-FOR") or
        request.environ.get("HTTP_X_FORWARDED_FOR")
    )
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs, the first is the original client
        ips = [ip.strip() for ip in forwarded_for.split(",")]
        if ips and ips[0]:
            return ips[0]

    # Fall back to X-Real-IP header
    real_ip = (
        request.headers.get("X-Real-IP") or
        request.headers.get("X-REAL-IP") or
        request.environ.get("HTTP_X_REAL_IP")
    )
    if real_ip:
        return real_ip

    # Fall back to remote_addr (also check environ for WebSocket)
    return request.remote_addr or request.environ.get("REMOTE_ADDR") or ""


def register_real_client_ip(real_ip: str) -> None:
    """Register a real client IP (from X-Forwarded-For/X-Real-IP) for analysis."""
    if real_ip and not is_local_ip(real_ip) and real_ip not in registered_real_ips:
        registered_real_ips.add(real_ip)
        # Trigger immediate analysis for this IP
        if fingerprinter:
            fingerprint = fingerprinter.analyze_ip(real_ip, force_ping=True)
            if fingerprint:
                socketio.emit("fingerprint_update", fingerprint.to_dict())


def create_app(start_capture: bool = True) -> Flask:
    global rtt_tracker, sniffer, geolocator, city_finder, fingerprinter, event_queue, database, local_ips

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = os.urandom(24)

    # Initialize event queue for cross-thread communication
    event_queue = Queue()

    # Detect local IPs to ignore
    local_ips = get_local_ips()

    # Initialize database
    database = get_database()

    # Initialize components
    rtt_tracker = RTTTracker()
    geolocator = GeoLocator()
    city_finder = CityFinder()
    fingerprinter = VPNFingerprinter(rtt_tracker, geolocator, city_finder, database=database)

    # Load persisted data from database
    loaded = fingerprinter.load_from_db()
    if loaded > 0:
        print(f"Restored {loaded} fingerprints from database")

    sniffer = PacketSniffer(rtt_tracker)
    sniffer.add_callback(queue_packet_event)  # Queue events instead of direct emit

    socketio.init_app(app)
    register_routes(app)

    if start_capture:
        sniffer.start()
        start_background_tasks()

    return app


def queue_packet_event(event_type: str, data: dict) -> None:
    """Queue events from sniffer thread for processing in eventlet context."""
    if event_queue is not None:
        event_queue.put((event_type, data))


def on_packet_event(event_type: str, data: dict) -> None:
    ip = data.get("ip")
    if not ip:
        return

    # Ignore local/server IPs
    if is_local_ip(ip):
        return

    if event_type == "new_connection":
        # Emit connection immediately, then start analysis in background
        socketio.emit("new_connection", {"ip": ip, "connection": data.get("connection")})
        # Try to get location and create initial fingerprint
        fingerprint = fingerprinter.analyze_ip(ip)
        if fingerprint:
            socketio.emit("fingerprint_update", fingerprint.to_dict())

    elif event_type == "rtt_update":
        fingerprint = fingerprinter.analyze_ip(ip)
        if fingerprint:
            socketio.emit("fingerprint_update", fingerprint.to_dict())


def start_background_tasks() -> None:
    def event_processor():
        """Process events from the queue in eventlet context."""
        while True:
            try:
                event_type, data = event_queue.get(timeout=0.1)
                on_packet_event(event_type, data)
            except Empty:
                pass
            except Exception:
                pass
            socketio.sleep(0)  # Yield to other greenlets

    def ping_worker():
        while True:
            socketio.sleep(10)
            try:
                # Combine IPs from packet capture and registered real IPs (from proxied requests)
                ips = sniffer.get_unique_remote_ips() | registered_real_ips
                for ip in list(ips)[:20]:  # Limit to 20 at a time
                    measurement = rtt_tracker.get_measurement(ip)
                    if measurement.icmp_rtt is None:
                        rtt_tracker.ping_ip(ip)
                        fingerprint = fingerprinter.analyze_ip(ip)
                        if fingerprint:
                            socketio.emit("fingerprint_update", fingerprint.to_dict())
                    socketio.sleep(0.1)  # Yield to other greenlets
            except Exception:
                pass

    def cleanup_worker():
        while True:
            socketio.sleep(60)
            try:
                sniffer.cleanup_old_connections()
                rtt_tracker.cleanup_stale()
                fingerprinter.cleanup_stale()
            except Exception:
                pass

    socketio.start_background_task(event_processor)
    socketio.start_background_task(ping_worker)
    socketio.start_background_task(cleanup_worker)


def register_routes(app: Flask) -> None:
    def filter_for_demo(data_dict: dict) -> dict:
        """In demo mode, filter to only show visitor's own IP."""
        if not config.demo_mode:
            return data_dict
        visitor_ip = get_visitor_ip()
        return {ip: fp for ip, fp in data_dict.items() if ip == visitor_ip}

    def filter_connections_for_demo(connections: list) -> list:
        """In demo mode, filter connections to only show visitor's own IP."""
        if not config.demo_mode:
            return connections
        visitor_ip = get_visitor_ip()
        # Connection has src_ip and dst_ip; the visitor's IP is the remote one
        return [c for c in connections if c.src_ip == visitor_ip or c.dst_ip == visitor_ip]

    @app.route("/")
    def index():
        # Register real client IP if behind proxy
        visitor_ip = get_visitor_ip()
        remote_addr = request.remote_addr or ""
        if visitor_ip != remote_addr:
            # Client is behind a proxy, register their real IP for analysis
            register_real_client_ip(visitor_ip)
        return render_template("index.html")

    @app.route("/api/connections")
    def get_connections():
        connections = sniffer.get_connections()
        filtered = filter_connections_for_demo(connections)
        return jsonify([c.to_dict() for c in filtered])

    @app.route("/api/fingerprints")
    def get_fingerprints():
        fingerprints = fingerprinter.get_all_fingerprints()
        filtered = filter_for_demo({ip: fp.to_dict() for ip, fp in fingerprints.items()})
        return jsonify(filtered)

    @app.route("/api/fingerprint/<ip>")
    def get_fingerprint(ip: str):
        # In demo mode, only allow querying visitor's own IP
        if config.demo_mode:
            visitor_ip = get_visitor_ip()
            if ip != visitor_ip:
                return jsonify({"error": "Access denied in demo mode"}), 403

        # Rate limit refreshes to once per second per IP
        force_ping = can_refresh_ip(ip)
        fingerprint = fingerprinter.analyze_ip(ip, force_ping=force_ping)
        if fingerprint:
            return jsonify(fingerprint.to_dict())
        return jsonify({"error": "No data available for this IP"}), 404

    @app.route("/api/location/<ip>")
    def get_location(ip: str):
        # In demo mode, only allow querying visitor's own IP
        if config.demo_mode:
            visitor_ip = get_visitor_ip()
            if ip != visitor_ip:
                return jsonify({"error": "Access denied in demo mode"}), 403

        location = geolocator.lookup(ip)
        if location:
            return jsonify(location.to_dict())
        return jsonify({"error": "Could not locate IP"}), 404

    @app.route("/api/stats")
    def get_stats():
        connections = sniffer.get_connections()
        fingerprints = fingerprinter.get_all_fingerprints()

        # Filter for demo mode
        if config.demo_mode:
            visitor_ip = get_visitor_ip()
            connections = [c for c in connections if c.src_ip == visitor_ip or c.dst_ip == visitor_ip]
            fingerprints = {ip: fp for ip, fp in fingerprints.items() if ip == visitor_ip}
            unique_ips = {visitor_ip} if visitor_ip in fingerprints else set()
        else:
            unique_ips = sniffer.get_unique_remote_ips()

        vpn_likely = sum(1 for fp in fingerprints.values() if fp.is_vpn_likely)

        return jsonify({
            "active_connections": len(connections),
            "unique_ips": len(unique_ips),
            "analyzed_ips": len(fingerprints),
            "vpn_likely": vpn_likely,
        })

    @app.route("/api/config")
    def get_config():
        return jsonify({
            "interface": config.interface,
            "port_filter": config.port_filter,
            "connection_timeout": config.connection_timeout,
            "demo_mode": config.demo_mode,
        })


@socketio.on("connect")
def handle_connect():
    # Register real client IP if behind proxy
    visitor_ip = get_visitor_ip()
    remote_addr = request.remote_addr or request.environ.get("REMOTE_ADDR") or ""
    if visitor_ip != remote_addr:
        # Client is behind a proxy, register their real IP for analysis
        register_real_client_ip(visitor_ip)

    fingerprints = fingerprinter.get_all_fingerprints()

    # Filter for demo mode
    if config.demo_mode:
        fingerprints = {ip: fp for ip, fp in fingerprints.items() if ip == visitor_ip}

    for ip, fp in fingerprints.items():
        emit("fingerprint_update", fp.to_dict())


@socketio.on("request_refresh")
def handle_refresh(data):
    ip = data.get("ip")
    if not ip:
        return

    # In demo mode, only allow refreshing visitor's own IP
    if config.demo_mode:
        visitor_ip = get_visitor_ip()
        if ip != visitor_ip:
            return

    # Rate limit refreshes to once per second per IP
    force_ping = can_refresh_ip(ip)
    fingerprint = fingerprinter.analyze_ip(ip, force_ping=force_ping)
    if fingerprint:
        emit("fingerprint_update", fingerprint.to_dict())
