import json
import threading
import time
from dataclasses import dataclass
from typing import Optional
from functools import lru_cache
import urllib.request
import urllib.error

from ..config import config


@dataclass
class GeoLocation:
    ip: str
    latitude: float
    longitude: float
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    timezone: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "city": self.city,
            "region": self.region,
            "country": self.country,
            "country_code": self.country_code,
            "isp": self.isp,
            "org": self.org,
            "timezone": self.timezone,
        }


class GeoLocator:
    def __init__(self, geoip_db_path: Optional[str] = None):
        self.geoip_db_path = geoip_db_path or config.geoip_db_path
        self._cache: dict[str, GeoLocation] = {}
        self._cache_time: dict[str, float] = {}
        self._lock = threading.Lock()
        self._geoip_reader = None
        self._init_maxmind()

    def _init_maxmind(self) -> None:
        if not self.geoip_db_path:
            return
        try:
            import geoip2.database
            self._geoip_reader = geoip2.database.Reader(self.geoip_db_path)
        except Exception:
            self._geoip_reader = None

    def _lookup_maxmind(self, ip: str) -> Optional[GeoLocation]:
        if not self._geoip_reader:
            return None
        try:
            response = self._geoip_reader.city(ip)
            return GeoLocation(
                ip=ip,
                latitude=response.location.latitude,
                longitude=response.location.longitude,
                city=response.city.name,
                region=response.subdivisions.most_specific.name if response.subdivisions else None,
                country=response.country.name,
                country_code=response.country.iso_code,
            )
        except Exception:
            return None

    def _lookup_ipapi(self, ip: str) -> Optional[GeoLocation]:
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org"
            req = urllib.request.Request(url, headers={"User-Agent": "parkranger/1.0"})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())

            if data.get("status") == "success":
                return GeoLocation(
                    ip=ip,
                    latitude=data.get("lat", 0),
                    longitude=data.get("lon", 0),
                    city=data.get("city"),
                    region=data.get("regionName"),
                    country=data.get("country"),
                    country_code=data.get("countryCode"),
                    isp=data.get("isp"),
                    org=data.get("org"),
                    timezone=data.get("timezone"),
                )
        except Exception:
            pass
        return None

    def _lookup_ipinfo(self, ip: str) -> Optional[GeoLocation]:
        try:
            url = f"https://ipinfo.io/{ip}/json"
            req = urllib.request.Request(url, headers={"User-Agent": "parkranger/1.0"})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())

            if "loc" in data:
                lat, lon = map(float, data["loc"].split(","))
                return GeoLocation(
                    ip=ip,
                    latitude=lat,
                    longitude=lon,
                    city=data.get("city"),
                    region=data.get("region"),
                    country=data.get("country"),
                    org=data.get("org"),
                )
        except Exception:
            pass
        return None

    def lookup(self, ip: str, use_cache: bool = True) -> Optional[GeoLocation]:
        if self._is_private_ip(ip):
            return None

        cache_ttl = 3600.0  # 1 hour

        with self._lock:
            if use_cache and ip in self._cache:
                if time.time() - self._cache_time.get(ip, 0) < cache_ttl:
                    return self._cache[ip]

        # Try MaxMind first if available
        result = self._lookup_maxmind(ip)

        # Fall back to free APIs
        if result is None:
            result = self._lookup_ipapi(ip)

        if result is None:
            result = self._lookup_ipinfo(ip)

        if result:
            with self._lock:
                self._cache[ip] = result
                self._cache_time[ip] = time.time()

        return result

    def _is_private_ip(self, ip: str) -> bool:
        if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
            return True
        if ip.startswith("172."):
            try:
                second_octet = int(ip.split(".")[1])
                if 16 <= second_octet <= 31:
                    return True
            except (ValueError, IndexError):
                pass
        return False

    def get_cached(self) -> dict[str, GeoLocation]:
        with self._lock:
            return dict(self._cache)

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()
            self._cache_time.clear()
