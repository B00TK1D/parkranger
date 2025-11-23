import gzip
import json
import os
import shutil
import tarfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..config import config

GEOLITE2_CITY_URL = "https://git.io/GeoLite2-City.mmdb"
DBIP_CITY_URL = "https://download.db-ip.com/free/dbip-city-lite-{year}-{month}.mmdb.gz"


def get_data_dir() -> Path:
    data_dir = Path.home() / ".parkranger"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


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


class GeoIPDownloader:
    @staticmethod
    def download_geolite2(dest_path: Path) -> bool:
        try:
            print(f"Downloading GeoLite2-City database...")
            req = urllib.request.Request(GEOLITE2_CITY_URL, headers={"User-Agent": "parkranger/1.0"})
            with urllib.request.urlopen(req, timeout=60) as response:
                with open(dest_path, "wb") as f:
                    shutil.copyfileobj(response, f)
            print(f"Downloaded GeoLite2-City database to {dest_path}")
            return True
        except Exception as e:
            print(f"Failed to download GeoLite2-City: {e}")
            return False

    @staticmethod
    def download_dbip(dest_path: Path) -> bool:
        now = time.gmtime()
        url = DBIP_CITY_URL.format(year=now.tm_year, month=f"{now.tm_mon:02d}")

        try:
            print(f"Downloading DB-IP City Lite database...")
            req = urllib.request.Request(url, headers={"User-Agent": "parkranger/1.0"})
            gz_path = dest_path.with_suffix(".mmdb.gz")

            with urllib.request.urlopen(req, timeout=120) as response:
                with open(gz_path, "wb") as f:
                    shutil.copyfileobj(response, f)

            with gzip.open(gz_path, "rb") as f_in:
                with open(dest_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)

            gz_path.unlink()
            print(f"Downloaded DB-IP City Lite database to {dest_path}")
            return True
        except Exception as e:
            print(f"Failed to download DB-IP: {e}")
            return False

    @classmethod
    def ensure_database(cls, db_path: Optional[str] = None) -> Optional[Path]:
        if db_path and Path(db_path).exists():
            return Path(db_path)

        data_dir = get_data_dir()
        default_db = data_dir / "GeoLite2-City.mmdb"

        if default_db.exists():
            age_days = (time.time() - default_db.stat().st_mtime) / 86400
            if age_days < 30:
                return default_db

        if cls.download_geolite2(default_db):
            return default_db

        dbip_path = data_dir / "dbip-city-lite.mmdb"
        if cls.download_dbip(dbip_path):
            return dbip_path

        if default_db.exists():
            return default_db

        return None


class GeoLocator:
    def __init__(self, geoip_db_path: Optional[str] = None, auto_download: bool = True):
        self.geoip_db_path = geoip_db_path or config.geoip_db_path
        self._cache: dict[str, GeoLocation] = {}
        self._cache_time: dict[str, float] = {}
        self._lock = threading.Lock()
        self._geoip_reader = None
        self._auto_download = auto_download
        self._init_geoip()

    def _init_geoip(self) -> None:
        db_path = self.geoip_db_path

        if not db_path and self._auto_download:
            result = GeoIPDownloader.ensure_database()
            if result:
                db_path = str(result)

        if not db_path:
            return

        try:
            import geoip2.database
            self._geoip_reader = geoip2.database.Reader(db_path)
            print(f"Loaded GeoIP database: {db_path}")
        except Exception as e:
            print(f"Failed to load GeoIP database: {e}")
            self._geoip_reader = None

    def _lookup_geoip(self, ip: str) -> Optional[GeoLocation]:
        if not self._geoip_reader:
            return None
        try:
            response = self._geoip_reader.city(ip)
            return GeoLocation(
                ip=ip,
                latitude=response.location.latitude or 0,
                longitude=response.location.longitude or 0,
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

        cache_ttl = 3600.0

        with self._lock:
            if use_cache and ip in self._cache:
                if time.time() - self._cache_time.get(ip, 0) < cache_ttl:
                    return self._cache[ip]

        result = self._lookup_geoip(ip)

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

    def has_local_database(self) -> bool:
        return self._geoip_reader is not None
