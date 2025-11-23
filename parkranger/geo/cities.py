import math
from dataclasses import dataclass
from typing import Optional


@dataclass
class City:
    name: str
    country: str
    latitude: float
    longitude: float
    population: int

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "country": self.country,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "population": self.population,
        }


# Major world cities with population > 500k (representative sample for performance)
MAJOR_CITIES = [
    City("Tokyo", "Japan", 35.6762, 139.6503, 37400068),
    City("Delhi", "India", 28.6139, 77.2090, 28514000),
    City("Shanghai", "China", 31.2304, 121.4737, 25582000),
    City("São Paulo", "Brazil", -23.5505, -46.6333, 21650000),
    City("Mexico City", "Mexico", 19.4326, -99.1332, 21581000),
    City("Cairo", "Egypt", 30.0444, 31.2357, 20076000),
    City("Mumbai", "India", 19.0760, 72.8777, 19980000),
    City("Beijing", "China", 39.9042, 116.4074, 19618000),
    City("Dhaka", "Bangladesh", 23.8103, 90.4125, 19578000),
    City("Osaka", "Japan", 34.6937, 135.5023, 19281000),
    City("New York", "USA", 40.7128, -74.0060, 18819000),
    City("Karachi", "Pakistan", 24.8607, 67.0011, 15400000),
    City("Buenos Aires", "Argentina", -34.6037, -58.3816, 14967000),
    City("Chongqing", "China", 29.4316, 106.9123, 14838000),
    City("Istanbul", "Turkey", 41.0082, 28.9784, 14751000),
    City("Kolkata", "India", 22.5726, 88.3639, 14681000),
    City("Manila", "Philippines", 14.5995, 120.9842, 13482000),
    City("Lagos", "Nigeria", 6.5244, 3.3792, 13463000),
    City("Rio de Janeiro", "Brazil", -22.9068, -43.1729, 13293000),
    City("Tianjin", "China", 39.3434, 117.3616, 13215000),
    City("Kinshasa", "DR Congo", -4.4419, 15.2663, 13171000),
    City("Guangzhou", "China", 23.1291, 113.2644, 12638000),
    City("Los Angeles", "USA", 34.0522, -118.2437, 12458000),
    City("Moscow", "Russia", 55.7558, 37.6173, 12410000),
    City("Shenzhen", "China", 22.5431, 114.0579, 11908000),
    City("Lahore", "Pakistan", 31.5497, 74.3436, 11738000),
    City("Bangalore", "India", 12.9716, 77.5946, 11440000),
    City("Paris", "France", 48.8566, 2.3522, 10901000),
    City("Bogotá", "Colombia", 4.7110, -74.0721, 10574000),
    City("Jakarta", "Indonesia", -6.2088, 106.8456, 10562000),
    City("Chennai", "India", 13.0827, 80.2707, 10456000),
    City("Lima", "Peru", -12.0464, -77.0428, 10391000),
    City("Bangkok", "Thailand", 13.7563, 100.5018, 10156000),
    City("Seoul", "South Korea", 37.5665, 126.9780, 9963000),
    City("Nagoya", "Japan", 35.1815, 136.9066, 9507000),
    City("Hyderabad", "India", 17.3850, 78.4867, 9482000),
    City("London", "UK", 51.5074, -0.1278, 9046000),
    City("Tehran", "Iran", 35.6892, 51.3890, 8896000),
    City("Chicago", "USA", 41.8781, -87.6298, 8864000),
    City("Chengdu", "China", 30.5728, 104.0668, 8813000),
    City("Nanjing", "China", 32.0603, 118.7969, 8505000),
    City("Wuhan", "China", 30.5928, 114.3055, 8364000),
    City("Ho Chi Minh City", "Vietnam", 10.8231, 106.6297, 8314000),
    City("Luanda", "Angola", -8.8390, 13.2894, 8045000),
    City("Ahmedabad", "India", 23.0225, 72.5714, 7681000),
    City("Kuala Lumpur", "Malaysia", 3.1390, 101.6869, 7564000),
    City("Hong Kong", "China", 22.3193, 114.1694, 7482000),
    City("Hangzhou", "China", 30.2741, 120.1551, 7236000),
    City("Riyadh", "Saudi Arabia", 24.7136, 46.6753, 7231000),
    City("Surat", "India", 21.1702, 72.8311, 6564000),
    City("Houston", "USA", 29.7604, -95.3698, 6371000),
    City("Dallas", "USA", 32.7767, -96.7970, 6366000),
    City("Pune", "India", 18.5204, 73.8567, 6276000),
    City("Singapore", "Singapore", 1.3521, 103.8198, 5850000),
    City("Santiago", "Chile", -33.4489, -70.6693, 5743000),
    City("Madrid", "Spain", 40.4168, -3.7038, 5631000),
    City("Toronto", "Canada", 43.6532, -79.3832, 5429000),
    City("Dar es Salaam", "Tanzania", -6.7924, 39.2083, 5383000),
    City("Johannesburg", "South Africa", -26.2041, 28.0473, 5283000),
    City("Barcelona", "Spain", 41.3851, 2.1734, 5258000),
    City("Saint Petersburg", "Russia", 59.9311, 30.3609, 5191000),
    City("Sydney", "Australia", -33.8688, 151.2093, 5131000),
    City("Melbourne", "Australia", -37.8136, 144.9631, 4850000),
    City("Phoenix", "USA", 33.4484, -112.0740, 4845000),
    City("Philadelphia", "USA", 39.9526, -75.1652, 4807000),
    City("San Francisco", "USA", 37.7749, -122.4194, 4731000),
    City("Nairobi", "Kenya", -1.2921, 36.8219, 4397000),
    City("Washington DC", "USA", 38.9072, -77.0369, 4384000),
    City("Boston", "USA", 42.3601, -71.0589, 4309000),
    City("Detroit", "USA", 42.3314, -83.0458, 3559000),
    City("Atlanta", "USA", 33.7490, -84.3880, 3500000),
    City("Miami", "USA", 25.7617, -80.1918, 3400000),
    City("Seattle", "USA", 47.6062, -122.3321, 3433000),
    City("Denver", "USA", 39.7392, -104.9903, 2727000),
    City("Minneapolis", "USA", 44.9778, -93.2650, 2474000),
    City("San Diego", "USA", 32.7157, -117.1611, 2381000),
    City("Berlin", "Germany", 52.5200, 13.4050, 3645000),
    City("Rome", "Italy", 41.9028, 12.4964, 4210000),
    City("Milan", "Italy", 45.4642, 9.1900, 3140000),
    City("Amsterdam", "Netherlands", 52.3676, 4.9041, 1140000),
    City("Vienna", "Austria", 48.2082, 16.3738, 1888000),
    City("Warsaw", "Poland", 52.2297, 21.0122, 1765000),
    City("Budapest", "Hungary", 47.4979, 19.0402, 1752000),
    City("Prague", "Czech Republic", 50.0755, 14.4378, 1301000),
    City("Brussels", "Belgium", 50.8503, 4.3517, 1175000),
    City("Stockholm", "Sweden", 59.3293, 18.0686, 1515000),
    City("Copenhagen", "Denmark", 55.6761, 12.5683, 1280000),
    City("Oslo", "Norway", 59.9139, 10.7522, 1019000),
    City("Helsinki", "Finland", 60.1695, 24.9354, 1268000),
    City("Dublin", "Ireland", 53.3498, -6.2603, 1173000),
    City("Lisbon", "Portugal", 38.7223, -9.1393, 2942000),
    City("Athens", "Greece", 37.9838, 23.7275, 3153000),
    City("Munich", "Germany", 48.1351, 11.5820, 1472000),
    City("Frankfurt", "Germany", 50.1109, 8.6821, 753000),
    City("Zurich", "Switzerland", 47.3769, 8.5417, 415000),
    City("Geneva", "Switzerland", 46.2044, 6.1432, 201000),
    City("Vancouver", "Canada", 49.2827, -123.1207, 2463000),
    City("Montreal", "Canada", 45.5017, -73.5673, 4098000),
    City("Calgary", "Canada", 51.0447, -114.0719, 1239000),
    City("Ottawa", "Canada", 45.4215, -75.6972, 934000),
    City("Tel Aviv", "Israel", 32.0853, 34.7818, 3785000),
    City("Dubai", "UAE", 25.2048, 55.2708, 3137000),
    City("Abu Dhabi", "UAE", 24.4539, 54.3773, 1420000),
    City("Doha", "Qatar", 25.2854, 51.5310, 956000),
    City("Kuwait City", "Kuwait", 29.3759, 47.9774, 2380000),
    City("Cape Town", "South Africa", -33.9249, 18.4241, 3740000),
    City("Auckland", "New Zealand", -36.8485, 174.7633, 1571000),
    City("Brisbane", "Australia", -27.4698, 153.0251, 2362000),
    City("Perth", "Australia", -31.9505, 115.8605, 2022000),
]


class CityFinder:
    def __init__(self):
        self.cities = MAJOR_CITIES

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

        for city in self.cities:
            distance = self.haversine_distance(center_lat, center_lon, city.latitude, city.longitude)
            distance_from_ring = abs(distance - ring_radius_km)

            if distance_from_ring <= tolerance_km:
                results.append({
                    **city.to_dict(),
                    "distance_from_center": distance,
                    "distance_from_ring": distance_from_ring,
                })

        # Sort by population (descending) as primary, distance from ring as secondary
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

        for city in self.cities:
            distance = self.haversine_distance(center_lat, center_lon, city.latitude, city.longitude)

            if distance <= radius_km:
                results.append({
                    **city.to_dict(),
                    "distance_from_center": distance,
                })

        results.sort(key=lambda x: -x["population"])
        return results[:max_results]

    def find_nearest_city(self, lat: float, lon: float) -> Optional[dict]:
        if not self.cities:
            return None

        nearest = None
        min_distance = float("inf")

        for city in self.cities:
            distance = self.haversine_distance(lat, lon, city.latitude, city.longitude)
            if distance < min_distance:
                min_distance = distance
                nearest = {**city.to_dict(), "distance": distance}

        return nearest
