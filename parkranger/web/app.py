import os
import threading
import time

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO

from ..capture.sniffer import PacketSniffer
from ..capture.rtt import RTTTracker
from ..geo.location import GeoLocator
from ..geo.cities import CityFinder
from ..analysis.fingerprint import VPNFingerprinter
from ..config import config


socketio = SocketIO(cors_allowed_origins="*", async_mode="eventlet")

rtt_tracker: RTTTracker = None
sniffer: PacketSniffer = None
geolocator: GeoLocator = None
city_finder: CityFinder = None
fingerprinter: VPNFingerprinter = None


def create_app(start_capture: bool = True) -> Flask:
    global rtt_tracker, sniffer, geolocator, city_finder, fingerprinter

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = os.urandom(24)

    # Initialize components
    rtt_tracker = RTTTracker()
    geolocator = GeoLocator()
    city_finder = CityFinder()
    fingerprinter = VPNFingerprinter(rtt_tracker, geolocator, city_finder)

    sniffer = PacketSniffer(rtt_tracker)
    sniffer.add_callback(on_packet_event)

    socketio.init_app(app)
    register_routes(app)

    if start_capture:
        sniffer.start()
        start_background_tasks()

    return app


def on_packet_event(event_type: str, data: dict) -> None:
    ip = data.get("ip")
    if not ip:
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
    def ping_worker():
        while True:
            time.sleep(10)
            try:
                ips = sniffer.get_unique_remote_ips()
                for ip in list(ips)[:20]:  # Limit to 20 at a time
                    measurement = rtt_tracker.get_measurement(ip)
                    if measurement.icmp_rtt is None:
                        rtt_tracker.ping_ip(ip)
                        fingerprint = fingerprinter.analyze_ip(ip)
                        if fingerprint:
                            socketio.emit("fingerprint_update", fingerprint.to_dict())
            except Exception:
                pass

    def cleanup_worker():
        while True:
            time.sleep(60)
            try:
                sniffer.cleanup_old_connections()
                rtt_tracker.cleanup_stale()
                fingerprinter.cleanup_stale()
            except Exception:
                pass

    threading.Thread(target=ping_worker, daemon=True).start()
    threading.Thread(target=cleanup_worker, daemon=True).start()


def register_routes(app: Flask) -> None:
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/connections")
    def get_connections():
        connections = sniffer.get_connections()
        return jsonify([c.to_dict() for c in connections])

    @app.route("/api/fingerprints")
    def get_fingerprints():
        fingerprints = fingerprinter.get_all_fingerprints()
        return jsonify({ip: fp.to_dict() for ip, fp in fingerprints.items()})

    @app.route("/api/fingerprint/<ip>")
    def get_fingerprint(ip: str):
        fingerprint = fingerprinter.analyze_ip(ip, force_ping=True)
        if fingerprint:
            return jsonify(fingerprint.to_dict())
        return jsonify({"error": "No data available for this IP"}), 404

    @app.route("/api/location/<ip>")
    def get_location(ip: str):
        location = geolocator.lookup(ip)
        if location:
            return jsonify(location.to_dict())
        return jsonify({"error": "Could not locate IP"}), 404

    @app.route("/api/stats")
    def get_stats():
        connections = sniffer.get_connections()
        fingerprints = fingerprinter.get_all_fingerprints()
        vpn_likely = sum(1 for fp in fingerprints.values() if fp.is_vpn_likely)

        return jsonify({
            "active_connections": len(connections),
            "unique_ips": len(sniffer.get_unique_remote_ips()),
            "analyzed_ips": len(fingerprints),
            "vpn_likely": vpn_likely,
        })

    @app.route("/api/config")
    def get_config():
        return jsonify({
            "interface": config.interface,
            "port_filter": config.port_filter,
            "connection_timeout": config.connection_timeout,
        })


@socketio.on("connect")
def handle_connect():
    fingerprints = fingerprinter.get_all_fingerprints()
    for ip, fp in fingerprints.items():
        socketio.emit("fingerprint_update", fp.to_dict())


@socketio.on("request_refresh")
def handle_refresh(data):
    ip = data.get("ip")
    if ip:
        fingerprint = fingerprinter.analyze_ip(ip, force_ping=True)
        if fingerprint:
            socketio.emit("fingerprint_update", fingerprint.to_dict())
