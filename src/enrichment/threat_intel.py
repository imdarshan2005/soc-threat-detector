"""
Threat Intelligence and IP Reputation Enrichment Service.
Simulates GeoIP lookups, ISP telemetry, and Threat Intel correlation.
"""
from typing import Dict, Any, Optional
from src.database.db_manager import DatabaseManager

# Synthetic GeoIP & ASN database for demonstration realism
GEOIP_LOOKUP_TABLE = {
    "198.51.100.23": {"country": "Russia", "code": "RU", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "asn": "AS42118", "isp": "RosTeleNet"},
    "203.0.113.45": {"country": "Netherlands", "code": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041, "asn": "AS1136", "isp": "KPN Telecom"},
    "192.0.2.100": {"country": "China", "code": "CN", "city": "Shenzhen", "lat": 22.5431, "lon": 114.0579, "asn": "AS4134", "isp": "China Telecom"},
    "185.220.101.5": {"country": "Germany", "code": "DE", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "asn": "AS20773", "isp": "HostEurope GmbH"},
    "45.33.32.156": {"country": "United States", "code": "US", "city": "Fremont", "lat": 37.5485, "lon": -121.9886, "asn": "AS63949", "isp": "Linode LLC"},
    "10.0.1.50": {"country": "Internal Corp", "code": "LAN", "city": "HQ Office", "lat": 0.0, "lon": 0.0, "asn": "RFC1918", "isp": "Internal Network"},
    "10.0.1.55": {"country": "Internal Corp", "code": "LAN", "city": "HQ Office", "lat": 0.0, "lon": 0.0, "asn": "RFC1918", "isp": "Internal Network"},
    "127.0.0.1": {"country": "Localhost", "code": "LOC", "city": "Loopback", "lat": 0.0, "lon": 0.0, "asn": "N/A", "isp": "Loopback Interface"}
}

class ThreatIntelService:
    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or DatabaseManager()

    def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Looks up reputation, geo-location, and Threat Intel details for an IP address."""
        ioc = self.db.lookup_threat_intel(ip)
        geo = GEOIP_LOOKUP_TABLE.get(ip, {
            "country": "Unknown External",
            "code": "XX",
            "city": "Unknown",
            "lat": 0.0,
            "lon": 0.0,
            "asn": "AS-UNKNOWN",
            "isp": "Commercial ISP"
        })

        if ioc:
            reputation = "MALICIOUS"
            risk_score = ioc.get("confidence", 85)
            threat_actor = ioc.get("threat_actor", "Unknown Threat Actor")
            threat_type = ioc.get("threat_type", "Known Threat Actor / Scanner")
            tags = ioc.get("tags", [])
        elif ip.startswith("10.") or ip.startswith("192.168.") or ip == "127.0.0.1":
            reputation = "TRUSTED INTERNAL"
            risk_score = 5
            threat_actor = "None"
            threat_type = "Authorized Corporate Asset"
            tags = ["internal", "corporate_lan"]
        else:
            reputation = "SUSPICIOUS" if "scanner" in geo.get("isp", "").lower() else "NEUTRAL"
            risk_score = 35
            threat_actor = "Unclassified"
            threat_type = "Public Internet Endpoint"
            tags = ["external_host"]

        return {
            "ip": ip,
            "reputation": reputation,
            "risk_score": risk_score,
            "threat_actor": threat_actor,
            "threat_type": threat_type,
            "tags": tags,
            "geo": geo
        }
