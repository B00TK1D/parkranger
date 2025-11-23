import threading
import time
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

from ..capture.rtt import RTTTracker, RTTMeasurement
from ..geo.location import GeoLocator, GeoLocation
from ..geo.cities import CityFinder
from ..config import config

if TYPE_CHECKING:
    from ..db import Database


@dataclass
class VPNFingerprint:
    ip: str
    location: Optional[GeoLocation] = None
    tcp_rtt_ms: Optional[float] = None
    icmp_rtt_ms: Optional[float] = None
    rtt_difference_ms: Optional[float] = None
    estimated_distance_km: Optional[float] = None
    possible_cities: list[dict] = field(default_factory=list)
    confidence: float = 0.0
    last_updated: float = field(default_factory=time.time)
    is_vpn_likely: bool = False

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "location": self.location.to_dict() if self.location else None,
            "tcp_rtt_ms": self.tcp_rtt_ms,
            "icmp_rtt_ms": self.icmp_rtt_ms,
            "rtt_difference_ms": self.rtt_difference_ms,
            "estimated_distance_km": self.estimated_distance_km,
            "possible_cities": self.possible_cities,
            "confidence": self.confidence,
            "last_updated": self.last_updated,
            "is_vpn_likely": self.is_vpn_likely,
        }


class VPNFingerprinter:
    def __init__(self, rtt_tracker: RTTTracker, geolocator: GeoLocator, city_finder: CityFinder, database: Optional["Database"] = None):
        self.rtt_tracker = rtt_tracker
        self.geolocator = geolocator
        self.city_finder = city_finder
        self._fingerprints: dict[str, VPNFingerprint] = {}
        self._lock = threading.Lock()
        self._db = database

    def _rtt_to_distance_km(self, rtt_ms: float) -> float:
        # RTT is round-trip, so divide by 2 for one-way
        # Speed of light in fiber is ~200,000 km/s or ~200 km/ms
        # But this is one-way, and we have RTT (round-trip)
        one_way_ms = rtt_ms / 2
        distance_km = one_way_ms * config.speed_of_light_km_ms
        return distance_km

    def _calculate_confidence(self, measurement: RTTMeasurement) -> float:
        # Need both TCP and ICMP samples for VPN detection confidence
        if not measurement.tcp_rtt_samples or not measurement.icmp_rtt_samples:
            # If we only have ICMP, we can still show location but no VPN detection
            if measurement.icmp_rtt_samples:
                return 0.1  # Low confidence, but not zero
            return 0.0

        # More samples = higher confidence
        tcp_sample_score = min(len(measurement.tcp_rtt_samples) / 10, 1.0)
        icmp_sample_score = min(len(measurement.icmp_rtt_samples) / 5, 1.0)

        # Lower variance = higher confidence
        if len(measurement.tcp_rtt_samples) > 1:
            tcp_variance = sum((x - measurement.tcp_rtt) ** 2 for x in measurement.tcp_rtt_samples) / len(measurement.tcp_rtt_samples)
            tcp_variance_score = max(0, 1 - (tcp_variance / 100))
        else:
            tcp_variance_score = 0.5

        base_confidence = (tcp_sample_score * 0.4 + icmp_sample_score * 0.3 + tcp_variance_score * 0.3)

        # If RTT difference is significant (>5ms), boost confidence that this is VPN
        if measurement.rtt_difference and measurement.rtt_difference > 5:
            base_confidence = min(base_confidence * 1.2, 1.0)

        return base_confidence

    def analyze_ip(self, ip: str, force_ping: bool = False) -> Optional[VPNFingerprint]:
        measurement = self.rtt_tracker.get_measurement(ip)

        # Get or create fingerprint
        with self._lock:
            if ip not in self._fingerprints:
                self._fingerprints[ip] = VPNFingerprint(ip=ip)
            fingerprint = self._fingerprints[ip]

        # Get geolocation
        if fingerprint.location is None:
            fingerprint.location = self.geolocator.lookup(ip)

        # Ping if needed (always ping if we don't have ICMP RTT yet)
        if measurement.icmp_rtt is None or force_ping:
            self.rtt_tracker.ping_ip(ip, force=force_ping)
            measurement = self.rtt_tracker.get_measurement(ip)

        # Update fingerprint
        fingerprint.tcp_rtt_ms = measurement.tcp_rtt
        fingerprint.icmp_rtt_ms = measurement.icmp_rtt
        fingerprint.confidence = self._calculate_confidence(measurement)
        fingerprint.last_updated = time.time()

        # Calculate adjusted RTT difference (subtract VPN internal processing latency)
        raw_diff = measurement.rtt_difference
        if raw_diff is not None:
            adjusted_diff = max(0, raw_diff - config.vpn_latency_offset_ms)
            fingerprint.rtt_difference_ms = adjusted_diff
        else:
            fingerprint.rtt_difference_ms = None

        # Calculate estimated distance from VPN if we have RTT difference
        if fingerprint.rtt_difference_ms is not None and fingerprint.rtt_difference_ms > 0:
            fingerprint.estimated_distance_km = self._rtt_to_distance_km(fingerprint.rtt_difference_ms)

            # Determine if VPN is likely (adjusted RTT difference > 0 suggests additional hop)
            fingerprint.is_vpn_likely = fingerprint.rtt_difference_ms > 0

            # Find cities near the estimated ring
            if fingerprint.location and fingerprint.estimated_distance_km > 0:
                tolerance = max(50, fingerprint.estimated_distance_km * 0.2)  # 20% tolerance or 50km minimum
                fingerprint.possible_cities = self.city_finder.find_cities_near_ring(
                    fingerprint.location.latitude,
                    fingerprint.location.longitude,
                    fingerprint.estimated_distance_km,
                    tolerance_km=tolerance,
                    max_results=10,
                )
        else:
            fingerprint.is_vpn_likely = False
            fingerprint.estimated_distance_km = None
            fingerprint.possible_cities = []

        with self._lock:
            self._fingerprints[ip] = fingerprint

        # Persist to database
        self._save_to_db(fingerprint)

        return fingerprint

    def _save_to_db(self, fingerprint: VPNFingerprint) -> None:
        if self._db is None:
            return
        try:
            self._db.save_fingerprint(
                ip=fingerprint.ip,
                location_dict=fingerprint.location.to_dict() if fingerprint.location else None,
                tcp_rtt_ms=fingerprint.tcp_rtt_ms,
                icmp_rtt_ms=fingerprint.icmp_rtt_ms,
                rtt_difference_ms=fingerprint.rtt_difference_ms,
                estimated_distance_km=fingerprint.estimated_distance_km,
                possible_cities=fingerprint.possible_cities,
                confidence=fingerprint.confidence,
                last_updated=fingerprint.last_updated,
                is_vpn_likely=fingerprint.is_vpn_likely,
            )
        except Exception:
            pass

    def load_from_db(self) -> int:
        if self._db is None:
            return 0

        try:
            fingerprints_data = self._db.load_all_fingerprints()
            loaded = 0
            with self._lock:
                for fp_data in fingerprints_data:
                    location = None
                    if fp_data["location"]:
                        loc = fp_data["location"]
                        location = GeoLocation(
                            ip=loc["ip"],
                            latitude=loc["latitude"],
                            longitude=loc["longitude"],
                            city=loc.get("city"),
                            region=loc.get("region"),
                            country=loc.get("country"),
                            country_code=loc.get("country_code"),
                            isp=loc.get("isp"),
                            org=loc.get("org"),
                            timezone=loc.get("timezone"),
                        )

                    fingerprint = VPNFingerprint(
                        ip=fp_data["ip"],
                        location=location,
                        tcp_rtt_ms=fp_data["tcp_rtt_ms"],
                        icmp_rtt_ms=fp_data["icmp_rtt_ms"],
                        rtt_difference_ms=fp_data["rtt_difference_ms"],
                        estimated_distance_km=fp_data["estimated_distance_km"],
                        possible_cities=fp_data["possible_cities"],
                        confidence=fp_data["confidence"],
                        last_updated=fp_data["last_updated"],
                        is_vpn_likely=fp_data["is_vpn_likely"],
                    )
                    self._fingerprints[fp_data["ip"]] = fingerprint
                    loaded += 1
            return loaded
        except Exception:
            return 0

    def get_fingerprint(self, ip: str) -> Optional[VPNFingerprint]:
        with self._lock:
            return self._fingerprints.get(ip)

    def get_all_fingerprints(self) -> dict[str, VPNFingerprint]:
        with self._lock:
            return dict(self._fingerprints)

    def analyze_all_active(self, ips: set[str]) -> list[VPNFingerprint]:
        results = []
        for ip in ips:
            fingerprint = self.analyze_ip(ip)
            if fingerprint:
                results.append(fingerprint)
        return results

    def cleanup_stale(self, max_age: float = 3600) -> int:
        now = time.time()
        with self._lock:
            stale_ips = [ip for ip, fp in self._fingerprints.items() if now - fp.last_updated > max_age]
            for ip in stale_ips:
                del self._fingerprints[ip]
                if self._db:
                    try:
                        self._db.delete_fingerprint(ip)
                    except Exception:
                        pass
            return len(stale_ips)
