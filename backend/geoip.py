"""
Geo-IP Lookup Service
Uses ip-api.com (free, no API key needed, 45 requests/min)
Caches results to avoid hitting rate limits
"""

import requests
import time
from collections import OrderedDict

# Simple LRU-style cache: {ip: {country, city, lat, lng, timestamp}}
_cache = OrderedDict()
_CACHE_MAX = 500
_CACHE_TTL = 3600   # 1 hour

# Private/reserved IP ranges — don't look these up
_PRIVATE_PREFIXES = (
    '10.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
    '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
    '172.30.', '172.31.', '192.168.', '127.', '0.', '::1',
    'localhost'
)

# Rate limiting
_last_request_time = 0
_MIN_INTERVAL = 1.5   # seconds between requests (stay under 45/min)


def is_private_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def lookup(ip: str) -> dict:
    """
    Look up geo location for an IP address.
    Returns dict with: country, country_code, city, region, lat, lng, isp
    Returns None for private IPs or on failure.
    """
    if not ip or is_private_ip(ip):
        return None

    # Check cache
    now = time.time()
    if ip in _cache:
        entry = _cache[ip]
        if now - entry['_cached_at'] < _CACHE_TTL:
            _cache.move_to_end(ip)   # LRU update
            return entry
        else:
            del _cache[ip]

    # Rate limiting
    global _last_request_time
    elapsed = now - _last_request_time
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)

    try:
        _last_request_time = time.time()
        response = requests.get(
            f'http://ip-api.com/json/{ip}',
            params={'fields': 'status,country,countryCode,regionName,city,lat,lon,isp,org'},
            timeout=3
        )
        data = response.json()

        if data.get('status') == 'success':
            result = {
                'country': data.get('country', ''),
                'country_code': data.get('countryCode', '').lower(),
                'city': data.get('city', ''),
                'region': data.get('regionName', ''),
                'lat': data.get('lat'),
                'lng': data.get('lon'),
                'isp': data.get('isp', ''),
                'org': data.get('org', ''),
                '_cached_at': time.time()
            }

            # Store in cache
            _cache[ip] = result
            if len(_cache) > _CACHE_MAX:
                _cache.popitem(last=False)   # Remove oldest

            return result

    except requests.exceptions.Timeout:
        pass   # Don't crash on timeout
    except Exception as e:
        print(f"⚠️  Geo-IP lookup failed for {ip}: {e}")

    return None


def lookup_batch(ips: list) -> dict:
    """Look up multiple IPs, returns {ip: geo_data}"""
    results = {}
    for ip in set(ips):   # deduplicate
        geo = lookup(ip)
        if geo:
            results[ip] = geo
    return results


def get_flag_emoji(country_code: str) -> str:
    """Convert 2-letter country code to flag emoji"""
    if not country_code or len(country_code) != 2:
        return '🌐'
    code = country_code.upper()
    return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)