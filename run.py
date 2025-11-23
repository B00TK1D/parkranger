#!/usr/bin/env python3
# Eventlet monkey patching must happen before any other imports
import eventlet
eventlet.monkey_patch()

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        description="ParkRanger - VPN Fingerprinting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python run.py                     # Run with defaults
  sudo python run.py -i eth0             # Capture on eth0
  sudo python run.py -p 80,443           # Only monitor ports 80 and 443
  sudo python run.py --host 127.0.0.1    # Bind web UI to localhost only
        """
    )

    parser.add_argument("-i", "--interface", help="Network interface to capture on")
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports to monitor (default: 80,443,8080,8443)")
    parser.add_argument("--host", default="0.0.0.0", help="Web server host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Web server port (default: 5000)")
    parser.add_argument("--geoip-db", help="Path to MaxMind GeoIP2 database file")
    parser.add_argument("--no-capture", action="store_true", help="Start without packet capture (web UI only)")
    parser.add_argument("--demo", action="store_true", help="Demo mode: filter traffic to show only visitor's own IP")

    args = parser.parse_args()

    # Update config from args
    from parkranger.config import config

    if args.interface:
        config.interface = args.interface
    if args.ports:
        config.port_filter = [int(p.strip()) for p in args.ports.split(",")]
    if args.geoip_db:
        config.geoip_db_path = args.geoip_db

    config.web_host = args.host
    config.web_port = args.port
    config.demo_mode = args.demo

    # Check for root/sudo (required for packet capture)
    import os
    if not args.no_capture and os.geteuid() != 0:
        print("Warning: Packet capture requires root privileges.")
        print("Run with sudo or use --no-capture for web UI only.")
        sys.exit(1)

    # Import and start app
    from parkranger.web.app import create_app, socketio

    app = create_app(start_capture=not args.no_capture)

    print(f"Starting ParkRanger on http://{config.web_host}:{config.web_port}")
    if config.demo_mode:
        print("Demo mode enabled: visitors will only see their own IP")
    if not args.no_capture:
        print(f"Capturing on interface: {config.interface or 'all'}")
        print(f"Monitoring ports: {config.port_filter}")

    socketio.run(app, host=config.web_host, port=config.web_port, debug=False)


if __name__ == "__main__":
    main()
