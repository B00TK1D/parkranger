import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

from .geo.location import get_data_dir


def get_db_path() -> Path:
    return get_data_dir() / "parkranger.db"


class Database:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or get_db_path()
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS fingerprints (
                ip TEXT PRIMARY KEY,
                location_json TEXT,
                tcp_rtt_ms REAL,
                icmp_rtt_ms REAL,
                rtt_difference_ms REAL,
                estimated_distance_km REAL,
                possible_cities_json TEXT,
                confidence REAL,
                last_updated REAL,
                is_vpn_likely INTEGER
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS geo_cache (
                ip TEXT PRIMARY KEY,
                latitude REAL,
                longitude REAL,
                city TEXT,
                region TEXT,
                country TEXT,
                country_code TEXT,
                isp TEXT,
                org TEXT,
                timezone TEXT,
                cached_at REAL
            )
        """)

        conn.commit()

    def save_fingerprint(
        self,
        ip: str,
        location_dict: Optional[dict],
        tcp_rtt_ms: Optional[float],
        icmp_rtt_ms: Optional[float],
        rtt_difference_ms: Optional[float],
        estimated_distance_km: Optional[float],
        possible_cities: list[dict],
        confidence: float,
        last_updated: float,
        is_vpn_likely: bool,
    ) -> None:
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO fingerprints
            (ip, location_json, tcp_rtt_ms, icmp_rtt_ms, rtt_difference_ms,
             estimated_distance_km, possible_cities_json, confidence, last_updated, is_vpn_likely)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                ip,
                json.dumps(location_dict) if location_dict else None,
                tcp_rtt_ms,
                icmp_rtt_ms,
                rtt_difference_ms,
                estimated_distance_km,
                json.dumps(possible_cities),
                confidence,
                last_updated,
                1 if is_vpn_likely else 0,
            ),
        )
        conn.commit()

    def load_all_fingerprints(self) -> list[dict]:
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM fingerprints")
        rows = cursor.fetchall()

        results = []
        for row in rows:
            fp = {
                "ip": row["ip"],
                "location": json.loads(row["location_json"]) if row["location_json"] else None,
                "tcp_rtt_ms": row["tcp_rtt_ms"],
                "icmp_rtt_ms": row["icmp_rtt_ms"],
                "rtt_difference_ms": row["rtt_difference_ms"],
                "estimated_distance_km": row["estimated_distance_km"],
                "possible_cities": json.loads(row["possible_cities_json"]) if row["possible_cities_json"] else [],
                "confidence": row["confidence"],
                "last_updated": row["last_updated"],
                "is_vpn_likely": bool(row["is_vpn_likely"]),
            }
            results.append(fp)

        return results

    def delete_fingerprint(self, ip: str) -> None:
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM fingerprints WHERE ip = ?", (ip,))
        conn.commit()

    def cleanup_old_fingerprints(self, max_age: float = 86400) -> int:
        conn = self._get_conn()
        cursor = conn.cursor()
        cutoff = time.time() - max_age
        cursor.execute("DELETE FROM fingerprints WHERE last_updated < ?", (cutoff,))
        deleted = cursor.rowcount
        conn.commit()
        return deleted

    def save_geo_cache(
        self,
        ip: str,
        latitude: float,
        longitude: float,
        city: Optional[str],
        region: Optional[str],
        country: Optional[str],
        country_code: Optional[str],
        isp: Optional[str],
        org: Optional[str],
        timezone: Optional[str],
    ) -> None:
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO geo_cache
            (ip, latitude, longitude, city, region, country, country_code, isp, org, timezone, cached_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (ip, latitude, longitude, city, region, country, country_code, isp, org, timezone, time.time()),
        )
        conn.commit()

    def load_geo_cache(self, max_age: float = 86400) -> list[dict]:
        conn = self._get_conn()
        cursor = conn.cursor()

        cutoff = time.time() - max_age
        cursor.execute("SELECT * FROM geo_cache WHERE cached_at > ?", (cutoff,))
        rows = cursor.fetchall()

        results = []
        for row in rows:
            results.append({
                "ip": row["ip"],
                "latitude": row["latitude"],
                "longitude": row["longitude"],
                "city": row["city"],
                "region": row["region"],
                "country": row["country"],
                "country_code": row["country_code"],
                "isp": row["isp"],
                "org": row["org"],
                "timezone": row["timezone"],
            })

        return results

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


# Global database instance
_db: Optional[Database] = None


def get_database() -> Database:
    global _db
    if _db is None:
        _db = Database()
    return _db
