import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Config:
    interface: Optional[str] = None
    port_filter: list[int] = field(default_factory=lambda: [80, 443, 8080, 8443])
    web_host: str = "0.0.0.0"
    web_port: int = 5000
    ping_timeout: float = 2.0
    ping_count: int = 3
    connection_timeout: int = 300
    max_connections: int = 1000
    geoip_db_path: Optional[str] = None
    speed_of_light_km_ms: float = 200.0  # ~2/3 speed of light in fiber
    vpn_latency_offset_ms: float = 0.0  # Internal VPN processing latency to subtract
    demo_mode: bool = False  # Filter traffic to only show visitor's own IP

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            interface=os.environ.get("PARKRANGER_INTERFACE"),
            port_filter=[int(p) for p in os.environ.get("PARKRANGER_PORTS", "80,443,8080,8443").split(",")],
            web_host=os.environ.get("PARKRANGER_HOST", "0.0.0.0"),
            web_port=int(os.environ.get("PARKRANGER_PORT", "5000")),
            ping_timeout=float(os.environ.get("PARKRANGER_PING_TIMEOUT", "2.0")),
            ping_count=int(os.environ.get("PARKRANGER_PING_COUNT", "3")),
            connection_timeout=int(os.environ.get("PARKRANGER_CONN_TIMEOUT", "300")),
            max_connections=int(os.environ.get("PARKRANGER_MAX_CONNS", "1000")),
            geoip_db_path=os.environ.get("PARKRANGER_GEOIP_DB"),
            vpn_latency_offset_ms=float(os.environ.get("PARKRANGER_VPN_LATENCY_OFFSET", "0.0")),
        )


config = Config.from_env()
