import math
from dataclasses import dataclass
from typing import Optional
from functools import lru_cache

import geonamescache


@dataclass
class City:
    name: str
    country: str
    country_code: str
    latitude: float
    longitude: float
    population: int

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "country": self.country,
            "country_code": self.country_code,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "population": self.population,
        }


class CityFinder:
    def __init__(self, min_population: int = 100000):
        self.min_population = min_population
        self._gc = geonamescache.GeonamesCache()
        self._cities: list[City] = []
        self._load_cities()

    def _load_cities(self) -> None:
        countries = self._gc.get_countries()
        cities_data = self._gc.get_cities()

        for city_id, city_info in cities_data.items():
            population = city_info.get("population", 0)
            if population < self.min_population:
                continue

            country_code = city_info.get("countrycode", "")
            country_name = countries.get(country_code, {}).get("name", country_code)

            self._cities.append(City(
                name=city_info.get("name", ""),
                country=country_name,
                country_code=country_code,
                latitude=city_info.get("latitude", 0),
                longitude=city_info.get("longitude", 0),
                population=population,
            ))

        self._cities.sort(key=lambda c: -c.population)

    @property
    def cities(self) -> list[City]:
        return self._cities

    @staticmethod
    def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        R = 6371  # Earth's radius in km
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)

        a = math.sin(delta_lat / 2) ** 2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return R * c

    def find_cities_near_ring(
        self,
        center_lat: float,
        center_lon: float,
        ring_radius_km: float,
        tolerance_km: float = 100,
        max_results: int = 10,
    ) -> list[dict]:
        results = []

        for city in self._cities:
            distance = self.haversine_distance(center_lat, center_lon, city.latitude, city.longitude)
            distance_from_ring = abs(distance - ring_radius_km)

            if distance_from_ring <= tolerance_km:
                results.append({
                    **city.to_dict(),
                    "distance_from_center": distance,
                    "distance_from_ring": distance_from_ring,
                })

        results.sort(key=lambda x: (-x["population"], x["distance_from_ring"]))
        return results[:max_results]

    def find_cities_within_radius(
        self,
        center_lat: float,
        center_lon: float,
        radius_km: float,
        max_results: int = 10,
    ) -> list[dict]:
        results = []

        for city in self._cities:
            distance = self.haversine_distance(center_lat, center_lon, city.latitude, city.longitude)

            if distance <= radius_km:
                results.append({
                    **city.to_dict(),
                    "distance_from_center": distance,
                })

        results.sort(key=lambda x: -x["population"])
        return results[:max_results]

    def find_nearest_city(self, lat: float, lon: float) -> Optional[dict]:
        if not self._cities:
            return None

        nearest = None
        min_distance = float("inf")

        for city in self._cities:
            distance = self.haversine_distance(lat, lon, city.latitude, city.longitude)
            if distance < min_distance:
                min_distance = distance
                nearest = {**city.to_dict(), "distance": distance}

        return nearest

    def get_city_count(self) -> int:
        return len(self._cities)
