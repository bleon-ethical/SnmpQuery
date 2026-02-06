"""
Static Service Database for IP to Service Name Resolution
Add this file to your project as services.py

SnmpQuery - Network Discovery and Monitoring Tool
Copyright (C) 2025 Agustin Garcia Maiztegui

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

services.py - List of known networks to better describe netflow data
"""

import ipaddress
from functools import lru_cache

# ============================================================================
# SERVICE DATABASE
# ============================================================================

SERVICE_DB = {
    # ========== DNS SERVERS ==========
    "8.8.8.8": "Google DNS",
    "8.8.4.4": "Google DNS",
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS",
    
    # ========== GOOGLE / ALPHABET ==========
    "142.250.0.0/15": "Google",
    "172.217.0.0/16": "Google",
    "173.194.0.0/16": "Google",
    "216.58.192.0/19": "Google",
    "74.125.0.0/16": "Google",
    "64.233.160.0/19": "Google",
    "66.102.0.0/20": "Google",
    "66.249.80.0/20": "Google",
    "72.14.192.0/18": "Google",
    "209.85.128.0/17": "Google",
    "216.239.32.0/19": "Google",
    
    # ========== CLOUDFLARE ==========
    "104.16.0.0/13": "Cloudflare CDN",
    "104.24.0.0/14": "Cloudflare CDN",
    "172.64.0.0/13": "Cloudflare CDN",
    "173.245.48.0/20": "Cloudflare CDN",
    "103.21.244.0/22": "Cloudflare CDN",
    "103.22.200.0/22": "Cloudflare CDN",
    "103.31.4.0/22": "Cloudflare CDN",
    "141.101.64.0/18": "Cloudflare CDN",
    "108.162.192.0/18": "Cloudflare CDN",
    "190.93.240.0/20": "Cloudflare CDN",
    "188.114.96.0/20": "Cloudflare CDN",
    "197.234.240.0/22": "Cloudflare CDN",
    "198.41.128.0/17": "Cloudflare CDN",
    
    # ========== AMAZON / AWS ==========
    "3.0.0.0/8": "Amazon AWS",
    "13.32.0.0/15": "Amazon AWS",
    "13.224.0.0/14": "Amazon CloudFront",
    "13.248.0.0/16": "Amazon AWS",
    "15.177.0.0/16": "Amazon AWS",
    "18.0.0.0/8": "Amazon AWS",
    "34.192.0.0/12": "Amazon AWS",
    "35.72.0.0/13": "Amazon AWS",
    "44.192.0.0/11": "Amazon AWS",
    "52.0.0.0/8": "Amazon AWS",
    "54.0.0.0/8": "Amazon AWS",
    "99.77.0.0/16": "Amazon CloudFront",
    "99.79.0.0/16": "Amazon CloudFront",
    "143.204.0.0/16": "Amazon CloudFront",
    "205.251.192.0/19": "Amazon CloudFront",
    "205.251.249.0/24": "Amazon CloudFront",
    "205.251.250.0/23": "Amazon CloudFront",
    
    # ========== MICROSOFT / AZURE / OFFICE 365 ==========
    "13.64.0.0/11": "Microsoft Azure",
    "13.104.0.0/14": "Microsoft",
    "20.0.0.0/8": "Microsoft",
    "23.96.0.0/13": "Microsoft Azure",
    "40.64.0.0/10": "Microsoft Azure",
    "51.0.0.0/8": "Microsoft Azure",
    "52.96.0.0/12": "Microsoft Office 365",
    "52.112.0.0/14": "Microsoft Office 365",
    "104.40.0.0/13": "Microsoft Azure",
    "131.253.0.0/16": "Microsoft",
    "132.245.0.0/16": "Microsoft",
    "137.116.0.0/15": "Microsoft Azure",
    "157.54.0.0/15": "Microsoft",
    "157.56.0.0/14": "Microsoft",
    "168.61.0.0/16": "Microsoft Azure",
    "191.232.0.0/13": "Microsoft Azure",
    "204.79.197.0/24": "Microsoft Bing",
    
    # ========== FACEBOOK / META ==========
    "31.13.24.0/21": "Facebook",
    "31.13.64.0/18": "Facebook",
    "45.64.40.0/22": "Facebook",
    "66.220.144.0/20": "Facebook",
    "69.63.176.0/20": "Facebook",
    "69.171.224.0/19": "Facebook",
    "74.119.76.0/22": "Facebook",
    "102.132.96.0/20": "Facebook",
    "103.4.96.0/22": "Facebook",
    "129.134.0.0/16": "Facebook",
    "157.240.0.0/16": "Facebook",
    "173.252.64.0/18": "Facebook",
    "179.60.192.0/22": "Facebook",
    "185.60.216.0/22": "Facebook",
    "204.15.20.0/22": "Facebook",
    
    # ========== AKAMAI CDN ==========
    "23.0.0.0/12": "Akamai CDN",
    "95.100.0.0/15": "Akamai CDN",
    "96.6.0.0/15": "Akamai CDN",
    "104.64.0.0/14": "Akamai CDN",
    "184.24.0.0/13": "Akamai CDN",
    "2.16.0.0/13": "Akamai CDN",
    
    # ========== FASTLY CDN ==========
    "151.101.0.0/16": "Fastly CDN",
    "157.52.64.0/18": "Fastly CDN",
    "167.82.0.0/17": "Fastly CDN",
    "185.31.16.0/22": "Fastly CDN",
    "199.232.0.0/16": "Fastly CDN",
    
    # ========== NETFLIX ==========
    "23.246.0.0/18": "Netflix",
    "37.77.184.0/21": "Netflix",
    "45.57.0.0/17": "Netflix",
    "64.120.128.0/17": "Netflix",
    "66.197.128.0/17": "Netflix",
    "69.53.224.0/19": "Netflix",
    "108.175.32.0/20": "Netflix",
    "185.2.220.0/22": "Netflix",
    "185.9.188.0/22": "Netflix",
    "192.173.64.0/18": "Netflix",
    "198.38.96.0/19": "Netflix",
    "198.45.48.0/20": "Netflix",
    "208.75.76.0/22": "Netflix",
    
    # ========== APPLE ==========
    "17.0.0.0/8": "Apple",
    
    # ========== TWITTER / X ==========
    "192.133.76.0/22": "Twitter",
    "199.16.156.0/22": "Twitter",
    "199.59.148.0/22": "Twitter",
    "199.96.56.0/21": "Twitter",
    "202.160.128.0/22": "Twitter",
    "209.237.192.0/19": "Twitter",
    
    # ========== LINKEDIN ==========
    "108.174.0.0/16": "LinkedIn",
    "144.2.0.0/16": "LinkedIn",
    
    # ========== ZOOM ==========
    "3.7.35.0/25": "Zoom",
    "3.21.137.128/25": "Zoom",
    "3.22.11.0/24": "Zoom",
    "3.23.93.0/24": "Zoom",
    "3.25.41.128/25": "Zoom",
    "3.25.42.0/25": "Zoom",
    "3.235.69.0/25": "Zoom",
    "3.235.71.128/25": "Zoom",
    "3.235.72.128/25": "Zoom",
    "3.235.73.0/25": "Zoom",
    "3.235.82.0/23": "Zoom",
    "3.235.96.0/23": "Zoom",
    "8.5.128.0/23": "Zoom",
    "50.239.202.0/23": "Zoom",
    "50.239.204.0/24": "Zoom",
    "64.125.62.0/24": "Zoom",
    "64.211.144.0/24": "Zoom",
    "65.39.152.0/24": "Zoom",
    "69.174.57.0/24": "Zoom",
    "69.174.108.0/22": "Zoom",
    "99.79.20.0/25": "Zoom",
    "101.36.167.0/24": "Zoom",
    "103.122.166.0/23": "Zoom",
    "111.33.115.0/25": "Zoom",
    "111.33.181.0/25": "Zoom",
    "115.110.154.192/26": "Zoom",
    "115.114.56.192/26": "Zoom",
    "115.114.115.0/26": "Zoom",
    "115.114.131.0/26": "Zoom",
    "120.29.148.0/24": "Zoom",
    "129.151.0.0/19": "Zoom",
    "129.151.40.0/22": "Zoom",
    "129.151.48.0/20": "Zoom",
    "129.159.0.0/20": "Zoom",
    "129.159.160.0/19": "Zoom",
    "129.159.208.0/20": "Zoom",
    "130.61.164.0/22": "Zoom",
    "134.224.0.0/16": "Zoom",
    "140.238.128.0/24": "Zoom",
    "147.124.96.0/19": "Zoom",
    "147.124.224.0/19": "Zoom",
    "152.67.20.0/24": "Zoom",
    "152.67.118.0/24": "Zoom",
    "152.67.168.0/22": "Zoom",
    "152.67.180.0/24": "Zoom",
    "152.67.240.0/21": "Zoom",
    "152.70.224.0/21": "Zoom",
    "158.101.64.0/24": "Zoom",
    "160.1.56.128/25": "Zoom",
    "161.199.136.0/22": "Zoom",
    "162.12.232.0/22": "Zoom",
    "162.255.36.0/22": "Zoom",
    "165.1.189.0/24": "Zoom",
    "165.1.190.0/24": "Zoom",
    "168.138.16.0/22": "Zoom",
    "168.138.48.0/24": "Zoom",
    "168.138.56.0/21": "Zoom",
    "168.138.72.0/24": "Zoom",
    "168.138.74.0/25": "Zoom",
    "168.138.80.0/21": "Zoom",
    "168.138.96.0/22": "Zoom",
    "168.138.116.0/22": "Zoom",
    "168.138.244.0/24": "Zoom",
    "170.114.0.0/16": "Zoom",
    "173.231.80.0/20": "Zoom",
    "192.204.12.0/22": "Zoom",
    "193.122.16.0/20": "Zoom",
    "193.123.0.0/19": "Zoom",
    "193.123.40.0/21": "Zoom",
    "193.123.128.0/19": "Zoom",
    "198.251.128.0/17": "Zoom",
    "202.177.207.128/27": "Zoom",
    "204.80.104.0/21": "Zoom",
    "207.226.132.0/24": "Zoom",
    "209.9.211.0/24": "Zoom",
    "209.9.215.0/24": "Zoom",
    "213.19.144.0/24": "Zoom",
    "213.19.153.0/24": "Zoom",
    "213.244.140.0/24": "Zoom",
    
    # ========== DROPBOX ==========
    "108.160.160.0/20": "Dropbox",
    "162.125.0.0/16": "Dropbox",
    "199.47.216.0/22": "Dropbox",
    
    # ========== SLACK ==========
    "52.85.0.0/16": "Slack",
    "54.164.0.0/16": "Slack",
    "54.172.0.0/15": "Slack",
    
    # ========== SALESFORCE ==========
    "13.108.0.0/14": "Salesforce",
    "136.146.0.0/15": "Salesforce",
    "182.50.76.0/22": "Salesforce",
    "182.50.80.0/21": "Salesforce",
    
    # ========== SPOTIFY ==========
    "35.186.224.0/19": "Spotify",
    "104.154.0.0/15": "Spotify",
    
    # ========== WHATSAPP ==========
    "31.13.64.0/19": "WhatsApp",
    "31.13.96.0/19": "WhatsApp",
    "75.126.0.0/18": "WhatsApp",
    "169.45.0.0/16": "WhatsApp",
    
    # ========== TELEGRAM ==========
    "91.108.4.0/22": "Telegram",
    "91.108.8.0/22": "Telegram",
    "91.108.12.0/22": "Telegram",
    "91.108.16.0/22": "Telegram",
    "91.108.56.0/22": "Telegram",
    "149.154.160.0/20": "Telegram",
    "185.76.151.0/24": "Telegram",
    
    # ========== DISCORD ==========
    "66.22.196.0/22": "Discord",
    "66.22.200.0/21": "Discord",
    "66.22.208.0/20": "Discord",
    "66.22.224.0/19": "Discord",
    
    # ========== STEAM / VALVE ==========
    "103.10.124.0/23": "Steam",
    "103.10.124.0/24": "Steam",
    "103.28.54.0/23": "Steam",
    "146.66.152.0/21": "Steam",
    "155.133.224.0/19": "Steam",
    "162.254.192.0/21": "Steam",
    "185.25.182.0/23": "Steam",
    "190.217.33.0/24": "Steam",
    "192.69.96.0/22": "Steam",
    "205.185.194.0/24": "Steam",
    "205.196.6.0/24": "Steam",
    "208.64.200.0/22": "Steam",
    "208.78.164.0/22": "Steam",
    
    # ========== YOUTUBE (additional to Google ranges) ==========
    # (Most YouTube traffic is in Google ranges above)
    
    # ========== INSTAGRAM (part of Facebook/Meta) ==========
    # (Covered by Facebook ranges above)
    
    # ========== TIKTOK ==========
    "49.51.0.0/16": "TikTok",
    "161.117.0.0/16": "TikTok",
    "203.107.0.0/16": "TikTok",
    
    # ========== REDDIT ==========
    "151.101.0.0/16": "Reddit",
    "199.232.0.0/16": "Reddit",
    
    # ========== GITHUB ==========
    "140.82.112.0/20": "GitHub",
    "143.55.64.0/20": "GitHub",
    "185.199.108.0/22": "GitHub",
    "192.30.252.0/22": "GitHub",
    
    # ========== ADOBE ==========
    "193.104.215.0/24": "Adobe",
    
    # ========== ORACLE CLOUD ==========
    "129.146.0.0/16": "Oracle Cloud",
    "130.35.0.0/16": "Oracle Cloud",
    "132.145.0.0/16": "Oracle Cloud",
    "134.70.0.0/16": "Oracle Cloud",
    "138.1.0.0/16": "Oracle Cloud",
    "140.91.0.0/16": "Oracle Cloud",
    "147.154.0.0/16": "Oracle Cloud",
    "192.29.0.0/16": "Oracle Cloud",
    
    # ========== IBM CLOUD ==========
    "5.10.64.0/21": "IBM Cloud",
    "9.0.0.0/8": "IBM",
    "50.22.128.0/17": "IBM Cloud",
    "50.23.0.0/16": "IBM Cloud",
    "108.168.128.0/17": "IBM Cloud",
    "169.38.0.0/16": "IBM Cloud",
    "169.45.0.0/16": "IBM Cloud",
    "169.46.0.0/15": "IBM Cloud",
    "169.48.0.0/14": "IBM Cloud",
    "169.53.0.0/16": "IBM Cloud",
    "169.54.0.0/15": "IBM Cloud",
    "169.56.0.0/14": "IBM Cloud",
    "169.60.0.0/14": "IBM Cloud",
    
    # ========== GOOGLE CLOUD PLATFORM (GCP) ==========
    "34.64.0.0/10": "Google Cloud",
    "35.184.0.0/13": "Google Cloud",
    "35.192.0.0/12": "Google Cloud",
    "35.208.0.0/12": "Google Cloud",
    "107.167.160.0/19": "Google Cloud",
    "107.178.192.0/18": "Google Cloud",
    "130.211.0.0/16": "Google Cloud",
    "146.148.0.0/17": "Google Cloud",
    
    # ========== DIGITALOCEAN ==========
    "104.131.0.0/16": "DigitalOcean",
    "138.197.0.0/16": "DigitalOcean",
    "159.65.0.0/16": "DigitalOcean",
    "165.227.0.0/16": "DigitalOcean",
    "167.71.0.0/16": "DigitalOcean",
    "167.172.0.0/16": "DigitalOcean",
    "178.128.0.0/16": "DigitalOcean",
    "188.166.0.0/16": "DigitalOcean",
    "206.189.0.0/16": "DigitalOcean",
    
    # ========== LINODE ==========
    "45.33.0.0/16": "Linode",
    "45.56.0.0/16": "Linode",
    "50.116.0.0/16": "Linode",
    "66.175.208.0/20": "Linode",
    "69.164.192.0/18": "Linode",
    "72.14.176.0/20": "Linode",
    "74.207.224.0/19": "Linode",
    "96.126.96.0/19": "Linode",
    "97.107.128.0/18": "Linode",
    "104.237.128.0/17": "Linode",
    "139.144.0.0/16": "Linode",
    "170.187.128.0/17": "Linode",
    "172.104.0.0/15": "Linode",
    "173.255.192.0/18": "Linode",
    "192.155.80.0/20": "Linode",
    "198.58.96.0/19": "Linode",
    
    # ========== VULTR ==========
    "45.32.0.0/16": "Vultr",
    "45.76.0.0/16": "Vultr",
    "45.77.0.0/16": "Vultr",
    "64.120.0.0/16": "Vultr",
    "66.42.0.0/16": "Vultr",
    "95.179.0.0/16": "Vultr",
    "104.156.224.0/19": "Vultr",
    "107.191.32.0/19": "Vultr",
    "108.61.0.0/16": "Vultr",
    "144.202.0.0/16": "Vultr",
    "149.28.0.0/16": "Vultr",
    "155.138.128.0/17": "Vultr",
    "167.179.0.0/16": "Vultr",
    "199.247.0.0/16": "Vultr",
    "202.182.96.0/20": "Vultr",
    "207.148.0.0/18": "Vultr",
    "207.246.64.0/18": "Vultr",
}

# ============================================================================
# LOOKUP FUNCTIONS
# ============================================================================

@lru_cache(maxsize=10000)
def get_service_name(ip):
    """
    Get service name for an IP address
    
    Args:
        ip: IP address string (e.g., "8.8.8.8")
    
    Returns:
        Service name string or None if not found
        
    Example:
        >>> get_service_name("8.8.8.8")
        "Google DNS"
        >>> get_service_name("1.2.3.4")
        None
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        # Check exact match first (fastest)
        if ip in SERVICE_DB:
            return SERVICE_DB[ip]
        
        # Check CIDR ranges (slower but comprehensive)
        for cidr, service in SERVICE_DB.items():
            if '/' in cidr:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    if ip_obj in network:
                        return service
                except:
                    continue
        
        return None
    except:
        return None

def format_ip_with_service(ip):
    """
    Format IP with service name if known
    
    Args:
        ip: IP address string
    
    Returns:
        Formatted string: "8.8.8.8 (Google DNS)" or just "8.8.8.8"
        
    Example:
        >>> format_ip_with_service("8.8.8.8")
        "8.8.8.8 (Google DNS)"
        >>> format_ip_with_service("1.2.3.4")
        "1.2.3.4"
    """
    service = get_service_name(ip)
    if service:
        return f"{ip} ({service})"
    return ip

def get_service_name_short(ip):
    """
    Get short service name (without details)
    
    Args:
        ip: IP address string
    
    Returns:
        Short service name or None
        
    Example:
        >>> get_service_name_short("8.8.8.8")
        "Google"  # Instead of "Google DNS"
    """
    service = get_service_name(ip)
    if not service:
        return None
    
    # Simplify some names
    if "CDN" in service:
        return service.split()[0]  # "Akamai CDN" -> "Akamai"
    if "Cloud" in service:
        return service.split()[0]  # "Google Cloud" -> "Google"
    
    return service

# ============================================================================
# STATISTICS
# ============================================================================

def get_database_stats():
    """
    Get statistics about the service database
    
    Returns:
        Dict with stats
    """
    exact_matches = sum(1 for k in SERVICE_DB.keys() if '/' not in k)
    cidr_ranges = sum(1 for k in SERVICE_DB.keys() if '/' in k)
    
    # Count unique services
    unique_services = len(set(SERVICE_DB.values()))
    
    return {
        'total_entries': len(SERVICE_DB),
        'exact_ips': exact_matches,
        'cidr_ranges': cidr_ranges,
        'unique_services': unique_services
    }

# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    # Test some well-known IPs
    test_ips = [
        "8.8.8.8",
        "1.1.1.1",
        "142.250.185.46",  # Google
        "157.240.1.1",     # Facebook
        "52.45.23.45",     # AWS
        "1.2.3.4",         # Unknown
    ]
    
    print("Service Database Test")
    print("=" * 50)
    
    for ip in test_ips:
        service = get_service_name(ip)
        formatted = format_ip_with_service(ip)
        print(f"{ip:20s} -> {service or 'Unknown':20s} | {formatted}")
    
    print("\n" + "=" * 50)
    stats = get_database_stats()
    print(f"Database Statistics:")
    print(f"  Total entries: {stats['total_entries']}")
    print(f"  Exact IPs:     {stats['exact_ips']}")
    print(f"  CIDR ranges:   {stats['cidr_ranges']}")
    print(f"  Unique services: {stats['unique_services']}")
