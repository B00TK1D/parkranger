import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from ..capture.rtt import RTTTracker, RTTMeasurement
from ..geo.location import GeoLocator, GeoLocation
from ..geo.cities import CityFinder
from ..config import config


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
    def __init__(self, rtt_tracker: RTTTracker, geolocator: GeoLocator, city_finder: CityFinder):
        self.rtt_tracker = rtt_tracker
        self.geolocator = geolocator
        self.city_finder = city_finder
        self._fingerprints: dict[str, VPNFingerprint] = {}
        self._lock = threading.Lock()

    def _rtt_to_distance_km(self, rtt_ms: float) -> float:
        # RTT is round-trip, so divide by 2 for one-way
        # Speed of light in fiber is ~200,000 km/s or ~200 km/ms
        # But this is one-way, and we have RTT (round-trip)
        one_way_ms = rtt_ms / 2
        distance_km = one_way_ms * config.speed_of_light_km_ms
        return distance_km

    def _calculate_confidence(self, measurement: RTTMeasurement) -> float:
        if not measurement.tcp_rtt_samples or not measurement.icmp_rtt_samples:
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

        if measurement.tcp_rtt is None:
            return None

        # Get or create fingerprint
        with self._lock:
            if ip not in self._fingerprints:
                self._fingerprints[ip] = VPNFingerprint(ip=ip)
            fingerprint = self._fingerprints[ip]

        # Get geolocation
        if fingerprint.location is None:
            fingerprint.location = self.geolocator.lookup(ip)

        # Ping if needed
        if measurement.icmp_rtt is None or force_ping:
            self.rtt_tracker.ping_ip(ip, force=force_ping)
            measurement = self.rtt_tracker.get_measurement(ip)

        # Update fingerprint
        fingerprint.tcp_rtt_ms = measurement.tcp_rtt
        fingerprint.icmp_rtt_ms = measurement.icmp_rtt
        fingerprint.rtt_difference_ms = measurement.rtt_difference
        fingerprint.confidence = self._calculate_confidence(measurement)
        fingerprint.last_updated = time.time()

        # Calculate estimated distance from VPN if we have RTT difference
        if fingerprint.rtt_difference_ms is not None and fingerprint.rtt_difference_ms > 0:
            fingerprint.estimated_distance_km = self._rtt_to_distance_km(fingerprint.rtt_difference_ms)

            # Determine if VPN is likely (RTT difference > 5ms suggests additional hop)
            fingerprint.is_vpn_likely = fingerprint.rtt_difference_ms > 5

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

        return fingerprint

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
            return len(stale_ips)
