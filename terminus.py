#!/usr/bin/env python3
"""
================================================================================
  TERMINUS v3.5 - Internet Exposure Attack Surface Framework
  ──────────────────────────────────────────────────────────────────────────────
  Developed by:  🎃🥷 MojithaR 🥷🎃
  GitHub:        https://github.com/MojithaR/shodan-audit-tool

  Purpose:
  Terminus is a professional grade, Shodan-powered reconnaissance framework
  designed for SOC analysts and security engineers. It automates the discovery
  of public facing assets, identifies open ports, correlates CVE data, and
  generates structured intelligence reports (CSV, JSON, interactive maps).

  This is the definitive version (v3.5) - feature complete, performance 0ptimized,
  and production ready.
================================================================================
"""

# -----------------------------------------------------------------------------
# 1. IMPORTS & DEPENDENCIES
# -----------------------------------------------------------------------------
import shodan
import json
import os
import time
import sys
import logging
import argparse
import ipaddress
import signal
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict

import pandas as pd
import folium
from folium.plugins import MarkerCluster
from prettytable import PrettyTable
from tqdm import tqdm
from dotenv import load_dotenv
from colorama import init, Style

# Initialize Colorama for Windows/Linux terminal color compatibility
init(autoreset=True)

# -----------------------------------------------------------------------------
# 2. GLOBAL SIGNAL HANDLER (Graceful Shutdown)
# -----------------------------------------------------------------------------
def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully to prevent ugly stack traces."""
    print(f"\n\n{TerminusColor.RED_CRITICAL}{SYM_CRITICAL} Terminus shutdown requested. Exiting gracefully.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# -----------------------------------------------------------------------------
# 3. CUSTOM ANSI COLORS (Based on User's Hex Codes)
# -----------------------------------------------------------------------------
# Using 24-bit ANSI escape sequences for precise brand color matching.
class TerminusColor:
    """Container for the Terminus brand color palette."""
    # Common / Neutral tones (Green spectrum)
    GREEN_BRIGHT = "\033[38;2;173;255;0m"     # #adff00
    GREEN_DARK   = "\033[38;2;116;214;0m"     # #74d600
    GREEN_DEEP   = "\033[38;2;2;137;0m"       # #028900
    GREEN_MINT   = "\033[38;2;0;255;131m"     # #00ff83

    # Critical / Alert tones
    RED_CRITICAL = "\033[38;2;255;0;0m"       # #ff0000
    AMBER_WARN   = "\033[38;2;255;210;43m"    # #ffd22b

    # Reset to default terminal color
    RESET = Style.RESET_ALL

# -----------------------------------------------------------------------------
# 4. BRAND SYMBOLS
# -----------------------------------------------------------------------------
# Strategically placed to denote different levels of importance.
SYM_HEADER    = "۞"   # Top-level section dividers
SYM_CRITICAL  = "✠"   # Highly critical issues / vulnerabilities
SYM_HAZARD    = "☣"   # Biohazard / Severe risk indicators
SYM_ACTION    = "⌘"   # User actions or command prompts
SYM_PROGRESS  = "⥀"   # Looping / processing / progress indicators

# Creator signature badges (only used in banner and final credits)
BADGE_LEFT   = "🎃"
BADGE_RIGHT  = "🥷"

# -----------------------------------------------------------------------------
# 5. STARTUP ANIMATION UTILITIES
# -----------------------------------------------------------------------------
def animate_text(text: str, delay: float = 0.025, color: str = TerminusColor.GREEN_MINT):
    """
    Simulate a typewriter effect for the startup banner.
    This gives the tool a premium, "cyber" feel without being gaudy.
    """
    sys.stdout.write(color)
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write(TerminusColor.RESET)
    print()  # Newline after the animation

def show_startup_splash():
    """
    Display the animated Terminus startup banner.
    This is the first thing users see and establishes the brand identity.
    """
    # Clear the screen for a fresh look (optional, commented for safety)
    # os.system('cls' if os.name == 'nt' else 'clear')

    # Top Border
    print(TerminusColor.AMBER_WARN + "╔" + "═" * 78 + "╗")

    # Line 1: Title (animated)
    animate_text(f"{SYM_HEADER}  TERMINUS v3.5  {SYM_HEADER}", delay=0.04, color=TerminusColor.GREEN_BRIGHT)
    time.sleep(0.2)

    # Line 2: Subtitle (animated)
    animate_text("   Internet Exposure Attack Surface Framework", delay=0.02, color=TerminusColor.GREEN_DARK)
    time.sleep(0.2)

    # Separator
    print(TerminusColor.GREEN_DEEP + "   " + "─" * 60)
    time.sleep(0.15)

    # Line 3: Developer (animated with badges)
    animate_text(f"   {BADGE_LEFT}  Developer: MojithaR  {BADGE_RIGHT}", delay=0.03, color=TerminusColor.GREEN_MINT)
    time.sleep(0.15)

    # Line 4: GitHub (animated)
    animate_text("   GitHub:    MojithaR/shodan-audit-tool", delay=0.02, color=TerminusColor.GREEN_DARK)
    time.sleep(0.2)

    # Line 5: Mission Statement
    animate_text("   Purpose:   Automate external attack surface mapping for SOC teams.", delay=0.015, color=TerminusColor.GREEN_MINT)
    time.sleep(0.3)

    # Bottom Border
    print(TerminusColor.AMBER_WARN + "╚" + "═" * 78 + "╝")
    print()  # Extra newline for spacing

# -----------------------------------------------------------------------------
# 6. TERMINUS DATA MODEL
# -----------------------------------------------------------------------------
@dataclass
class HostIntel:
    """
    Structured data container for each discovered host.
    This enforces type safety and makes JSON serialization trivial.
    """
    ip: str
    country: str
    city: str
    latitude: float
    longitude: float
    org: str
    asn: str
    isp: str
    os: str
    ports: List[int]
    high_risk_ports: List[int]
    vulnerabilities: List[str]
    http_title: str
    services: List[Dict[str, Any]]
    last_update: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert dataclass to a JSON-serializable dictionary."""
        return asdict(self)


# -----------------------------------------------------------------------------
# 7. TERMINUS ENGINE (Core Logic)
# -----------------------------------------------------------------------------
class TerminusEngine:
    """
    The main reconnaissance engine. Responsible for querying Shodan,
    parsing responses, aggregating data, and generating reports.
    """

    # Mapping of high-risk ports with associated threats.
    HIGH_RISK_MAP = {
        21:   "FTP - Anonymous access",
        22:   "SSH - Brute force target",
        23:   "Telnet - Plaintext credentials",
        25:   "SMTP - Open relay risk",
        53:   "DNS - Amplification attacks",
        80:   "HTTP - Outdated web servers",
        110:  "POP3 - Legacy protocol",
        139:  "NetBIOS - Info disclosure",
        143:  "IMAP - Legacy protocol",
        161:  "SNMP - Default community strings",
        443:  "HTTPS - SSL/TLS misconfigs",
        445:  "SMB - EternalBlue vector",
        3306: "MySQL - Brute force & SQLi",
        3389: "RDP - BlueKeep / credential theft",
        5900: "VNC - Unauthenticated access",
        6379: "Redis - Unauthorized data exposure",
        9200: "Elasticsearch - Data leakage",
        1433: "MSSQL - Database compromise",
        27017: "MongoDB - Unauthorized access",
    }

    def __init__(self, api_key: str, debug: bool = False):
        """
        Initialize the engine with a valid Shodan API key.
        :param api_key: Your Shodan API key (loaded from .env or passed).
        :param debug: Enable verbose logging for troubleshooting.
        """
        self.api = shodan.Shodan(api_key)
        self.debug = debug
        self.results: List[HostIntel] = []
        self.raw_coords = []  # Used exclusively for the map generator

        # Global aggregation counters
        self.summary = {
            "total_hosts": 0,
            "total_ports": 0,
            "high_risk_count": 0,
            "vulnerabilities": set(),
            "countries": {},
            "unique_ports": {},
            "total_risk_score": 0.0
        }
        self._logger = logging.getLogger("Terminus")
        if debug:
            logging.basicConfig(level=logging.DEBUG)

    # -------------------------------------------------------------------------
    # 7.1. UTILITY METHODS (Safe Parsing & Retries)
    # -------------------------------------------------------------------------
    def _safe_get_vulns(self, host_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Safely extract vulnerabilities from the Shodan response.

        # FIX: Shodan's API inconsistently returns 'vulns' as a dict or a list.
        # If it returns an empty list [], dict comprehension fails.
        # We explicitly coerce it to an empty dict to prevent crashes.
        """
        vulns = host_data.get('vulns', {})
        if isinstance(vulns, list):
            return {}
        if not isinstance(vulns, dict):
            return {}
        return vulns

    def _retry_fetch(self, ip: str, retries: int = 2) -> Optional[Dict[str, Any]]:
        """
        Fetch host data from Shodan with automatic retry on transient failures.
        Rate-limiting triggers a 2-second sleep.
        """
        for attempt in range(retries):
            try:
                if self.debug:
                    self._logger.debug(f"Fetching data for {ip} (attempt {attempt+1})")
                return self.api.host(ip)
            except shodan.APIError as e:
                if "rate" in str(e).lower() or "limit" in str(e).lower():
                    self._logger.warning(f"Rate limit hit for {ip}. Sleeping 2s...")
                    time.sleep(2)
                    continue
                self._logger.error(f"Shodan API error for {ip}: {e}")
                return None
            except Exception as e:
                self._logger.error(f"Unexpected error for {ip}: {e}")
                return None
        return None

    def _parse_shodan_response(self, ip: str, host: Dict[str, Any]) -> Optional[HostIntel]:
        """
        Parse a raw Shodan host response into a structured HostIntel object.
        This enriches the data with HTTP titles, ASN, and ISP information.
        """
        try:
            ports = host.get('ports', [])
            vulns = self._safe_get_vulns(host)
            vuln_list = list(vulns.keys())
            high_risk = [p for p in ports if p in self.HIGH_RISK_MAP]

            # Extract HTTP title from the first service with port 80 or 443
            http_title = "N/A"
            for item in host.get('data', []):
                if item.get('port') in (80, 443) and 'http' in item.get('transport', ''):
                    banner = item.get('data', '')
                    if '<title>' in banner:
                        start = banner.find('<title>') + 7
                        end = banner.find('</title>')
                        if end != -1:
                            http_title = banner[start:end].strip()[:80]
                            break

            # Build service list with truncated banners for readability
            services = []
            for item in host.get('data', []):
                services.append({
                    'port': item.get('port'),
                    'transport': item.get('transport', 'tcp'),
                    'product': item.get('product', 'Unknown'),
                    'version': item.get('version', ''),
                    'banner': item.get('data', '')[:200]
                })

            # Update global summary statistics
            self.summary['total_ports'] += len(ports)
            self.summary['high_risk_count'] += len(high_risk)
            for p in ports:
                self.summary['unique_ports'][p] = self.summary['unique_ports'].get(p, 0) + 1
            self.summary['vulnerabilities'].update(vuln_list)

            country = host.get('country_name', 'Unknown')
            self.summary['countries'][country] = self.summary['countries'].get(country, 0) + 1

            # Build the structured object
            host_info = HostIntel(
                ip=ip,
                country=country,
                city=host.get('city', 'Unknown'),
                latitude=host.get('latitude', 0.0),
                longitude=host.get('longitude', 0.0),
                org=host.get('org', 'Unknown'),
                asn=host.get('asn', 'N/A'),
                isp=host.get('isp', 'N/A'),
                os=host.get('os', 'Unknown'),
                ports=ports,
                high_risk_ports=high_risk,
                vulnerabilities=vuln_list,
                http_title=http_title,
                services=services,
                last_update=host.get('last_update', '')
            )

            if host_info.latitude and host_info.longitude:
                self.raw_coords.append(host_info)

            return host_info

        except Exception as e:
            self._logger.error(f"Failed to parse host {ip}: {e}")
            return None

    # -------------------------------------------------------------------------
    # 7.2. TARGET RESOLUTION (Domain, IP, CIDR)
    # -------------------------------------------------------------------------
    def _resolve_target(self, target: str) -> Tuple[str, List[str]]:
        """
        Determine the nature of the input and build the appropriate Shodan query.

        Supports:
          - Domains:       "example.com"              -> hostname:example.com
          - IPv4 Address:  "192.168.1.1"              -> ip:192.168.1.1
          - CIDR Range:    "192.168.1.0/24"           -> net:192.168.1.0/24
        """
        try:
            ipaddress.ip_address(target)
            return "ip", [f"ip:{target}"]
        except ValueError:
            pass

        try:
            ipaddress.ip_network(target, strict=False)
            return "cidr", [f"net:{target}"]
        except ValueError:
            pass

        return "domain", [f"hostname:{target}"]

    # -------------------------------------------------------------------------
    # 7.3. FETCH EXECUTION (Multi-threaded with Progress Bar)
    # -------------------------------------------------------------------------
    def fetch_host_details(self, ip: str) -> Optional[HostIntel]:
        """Wrapper for _retry_fetch and _parse_shodan_response."""
        raw = self._retry_fetch(ip)
        if not raw:
            return None
        return self._parse_shodan_response(ip, raw)

    def run(self, target: str, limit: int = 50) -> List[HostIntel]:
        """
        Orchestrate the entire reconnaissance process.

        Steps:
          1. Resolve the target type (domain/IP/CIDR).
          2. Query Shodan to get a list of matching IPs.
          3. Fetch details for each IP concurrently (thread pool).
          4. Aggregate and store results.
        """
        print(f"\n{SYM_ACTION} {TerminusColor.GREEN_BRIGHT}Terminus Engine Initialized")
        print(f"{SYM_PROGRESS} Target: {TerminusColor.GREEN_MINT}{target}")

        target_type, queries = self._resolve_target(target)
        if self.debug:
            print(f"{SYM_PROGRESS} Detected type: {target_type}")

        # Search Shodan
        try:
            query_str = queries[0]
            print(f"{SYM_ACTION} Querying Shodan...")
            search_results = self.api.search(query_str, limit=limit)
            total_found = search_results['total']
            ips = [m['ip_str'] for m in search_results['matches']]

            print(f"{SYM_HEADER} Found {total_found} hosts. Processing {len(ips)} unique IPs.")

        except shodan.APIError as e:
            print(f"{TerminusColor.RED_CRITICAL}{SYM_CRITICAL} Shodan search failed: {e}")
            return []

        if not ips:
            print(f"{TerminusColor.AMBER_WARN}{SYM_CRITICAL} No IPs found for this target.")
            return []

        # Multi-threaded fetching with progress bar
        results_list = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.fetch_host_details, ip): ip for ip in ips}

            with tqdm(total=len(ips), desc=f"{SYM_PROGRESS} Scanning", unit="host") as pbar:
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results_list.append(result)
                    pbar.update(1)

        self.results = results_list
        self.summary['total_hosts'] = len(results_list)

        # Calculate average risk score
        if self.results:
            total_risk = 0.0
            for h in self.results:
                if len(h.ports) > 0:
                    risk_ratio = len(h.high_risk_ports) / len(h.ports)
                    total_risk += risk_ratio * 100
            self.summary['total_risk_score'] = total_risk / len(self.results)

        print(f"{TerminusColor.GREEN_DARK}{SYM_HEADER} Audit complete. {len(results_list)} hosts processed.")
        return results_list

    # -------------------------------------------------------------------------
    # 7.4. REPORT GENERATORS (Console, CSV, JSON, Map)
    # -------------------------------------------------------------------------
    def generate_reports(self, output_dir: str = "./audit_report"):
        """Generate all artifacts: Console summary, CSV, JSON, and interactive map."""
        os.makedirs(output_dir, exist_ok=True)

        self._print_console_report()
        self._export_csv(output_dir)
        self._export_json(output_dir)
        self._create_map(output_dir)

        # Final success message with creator signature
        print(f"\n{TerminusColor.GREEN_MINT}{SYM_HEADER} Reports saved to: {output_dir}/")
        print(f"{TerminusColor.GREEN_BRIGHT}  - audit_report.csv")
        print(f"{TerminusColor.GREEN_BRIGHT}  - audit_report.json")
        print(f"{TerminusColor.GREEN_BRIGHT}  - exposure_map.html")
        print(f"\n{TerminusColor.GREEN_MINT}Framework executed successfully.")
        print(f"{BADGE_LEFT} {TerminusColor.GREEN_BRIGHT}MojithaR {BADGE_RIGHT} {TerminusColor.GREEN_DARK}| https://github.com/MojithaR/shodan-audit-tool")

    def _print_console_report(self):
        """Display a professional summary in the terminal using the brand colors."""
        # ---- Brand Header ----
        print("\n" + "=" * 80)
        print(f"{TerminusColor.GREEN_BRIGHT}{SYM_HEADER} TERMINUS v3.5 {SYM_HEADER}")
        print(f"{TerminusColor.GREEN_DARK}  Internet Exposure Attack Surface Framework")
        print(f"{TerminusColor.GREEN_MINT}  {BADGE_LEFT} Developed by: MojithaR {BADGE_RIGHT}")
        print(f"  {SYM_ACTION} {TerminusColor.GREEN_DARK}GitHub: MojithaR/shodan-audit-tool")
        print("=" * 80)

        # ---- Scan Metadata ----
        print(f"{TerminusColor.GREEN_BRIGHT}Scan finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # ---- Key Metrics (Data Cards) ----
        print(f"\n{TerminusColor.AMBER_WARN}┌──────────────────────┬──────────────────────────────┐")
        print(f"│ {TerminusColor.GREEN_BRIGHT}Metric                {TerminusColor.AMBER_WARN}│ {TerminusColor.GREEN_BRIGHT}Value                         {TerminusColor.AMBER_WARN}│")
        print(f"├──────────────────────┼──────────────────────────────┤")
        print(f"│ {TerminusColor.GREEN_MINT}Total Hosts           {TerminusColor.AMBER_WARN}│ {TerminusColor.GREEN_MINT}{self.summary['total_hosts']:<28} {TerminusColor.AMBER_WARN}│")
        print(f"│ {TerminusColor.GREEN_MINT}Open Ports            {TerminusColor.AMBER_WARN}│ {TerminusColor.GREEN_MINT}{self.summary['total_ports']:<28} {TerminusColor.AMBER_WARN}│")
        print(f"│ {TerminusColor.RED_CRITICAL}High-Risk Ports      {TerminusColor.AMBER_WARN}│ {TerminusColor.RED_CRITICAL}{self.summary['high_risk_count']:<28} {TerminusColor.AMBER_WARN}│")
        print(f"│ {TerminusColor.AMBER_WARN}Unique Ports          {TerminusColor.AMBER_WARN}│ {TerminusColor.AMBER_WARN}{len(self.summary['unique_ports']):<28} {TerminusColor.AMBER_WARN}│")
        print(f"│ {TerminusColor.RED_CRITICAL}CVEs Found           {TerminusColor.AMBER_WARN}│ {TerminusColor.RED_CRITICAL}{len(self.summary['vulnerabilities']):<28} {TerminusColor.AMBER_WARN}│")
        print(f"│ {TerminusColor.GREEN_BRIGHT}Global Risk Score    {TerminusColor.AMBER_WARN}│ {TerminusColor.GREEN_BRIGHT}{self.summary['total_risk_score']:.1f}%{' ' * 25}{TerminusColor.AMBER_WARN}│")
        print(f"{TerminusColor.AMBER_WARN}└──────────────────────┴──────────────────────────────┘")

        # ---- Top 5 Open Ports ----
        if self.summary['unique_ports']:
            print(f"\n{TerminusColor.GREEN_BRIGHT}{SYM_HEADER} Top 5 Open Ports (Most Frequent)")
            sorted_ports = sorted(self.summary['unique_ports'].items(), key=lambda x: x[1], reverse=True)[:5]
            for port, count in sorted_ports:
                bar_len = min(30, count * 2)  # Scale for visualization
                bar = "█" * bar_len
                print(f"  {SYM_ACTION} Port {port:<5} : {bar} {count} host(s)")

        # ---- Geographic Risk Breakdown ----
        if self.summary['countries']:
            print(f"\n{TerminusColor.AMBER_WARN}{SYM_HEADER} Country Risk Breakdown")
            for country, count in sorted(self.summary['countries'].items(), key=lambda x: x[1], reverse=True)[:5]:
                # Color code based on number of hosts
                if count >= 5:
                    color = TerminusColor.RED_CRITICAL
                elif count >= 2:
                    color = TerminusColor.AMBER_WARN
                else:
                    color = TerminusColor.GREEN_MINT
                print(f"  {color}{country}: {count} host(s)")

        # ---- Top 15 Asset Table ----
        if self.results:
            table = PrettyTable()
            table.field_names = [
                f"{TerminusColor.GREEN_BRIGHT}IP",
                f"{TerminusColor.GREEN_BRIGHT}Country",
                f"{TerminusColor.GREEN_BRIGHT}Ports",
                f"{TerminusColor.RED_CRITICAL}High-Risk",
                f"{TerminusColor.RED_CRITICAL}CVEs",
                f"{TerminusColor.AMBER_WARN}Title"
            ]
            table.align = "l"
            table.max_width = 30

            for h in self.results[:15]:
                cve_display = f"{len(h.vulnerabilities)}" if h.vulnerabilities else "0"
                high_display = f"{len(h.high_risk_ports)}" if h.high_risk_ports else "0"
                title_display = h.http_title[:25] if h.http_title != "N/A" else "-"

                if high_display != "0":
                    high_display = f"{TerminusColor.RED_CRITICAL}{high_display}{TerminusColor.RESET}"
                else:
                    high_display = f"{TerminusColor.GREEN_DARK}{high_display}{TerminusColor.RESET}"

                table.add_row([
                    h.ip,
                    h.country,
                    len(h.ports),
                    high_display,
                    cve_display,
                    title_display
                ])

            print(f"\n{TerminusColor.AMBER_WARN}{SYM_HEADER} Top 15 Assets by Risk")
            print(table)

        # ---- Critical Vulnerability Alert ----
        if self.summary['vulnerabilities']:
            print(f"\n{TerminusColor.RED_CRITICAL}{SYM_HAZARD} CRITICAL VULNERABILITIES DETECTED")
            for v in list(self.summary['vulnerabilities'])[:10]:
                print(f"  {SYM_CRITICAL} {v}")

    # -------------------------------------------------------------------------
    # 7.5. EXPORT FUNCTIONS (CSV, JSON, Map)
    # -------------------------------------------------------------------------
    def _export_csv(self, output_dir: str):
        """Generate a CSV file suitable for Excel or SIEM ingestion."""
        data = []
        for h in self.results:
            # Calculate individual host risk score
            risk_score = 0.0
            if len(h.ports) > 0:
                risk_score = (len(h.high_risk_ports) / len(h.ports)) * 100

            data.append({
                'IP': h.ip,
                'Country': h.country,
                'City': h.city,
                'Organization': h.org,
                'ASN': h.asn,
                'ISP': h.isp,
                'OS': h.os,
                'Ports_Open': len(h.ports),
                'High_Risk_Ports': ', '.join(map(str, h.high_risk_ports)),
                'Risk_Score_Per_Host': f"{risk_score:.2f}%",
                'Vulnerabilities': ', '.join(h.vulnerabilities),
                'HTTP_Title': h.http_title,
                'Last_Updated': h.last_update
            })
        df = pd.DataFrame(data)
        df.to_csv(f"{output_dir}/audit_report.csv", index=False, encoding='utf-8-sig')

    def _export_json(self, output_dir: str):
        """Generate a JSON file with full structured data for APIs."""
        # Compile top 5 ports for the summary
        top_ports = sorted(self.summary['unique_ports'].items(), key=lambda x: x[1], reverse=True)[:5]

        serializable = {
            'metadata': {
                'generated': datetime.now().isoformat(),
                'framework': 'Terminus v3.5',
                'developer': 'MojithaR',
                'github': 'https://github.com/MojithaR/shodan-audit-tool',
                'total_hosts': self.summary['total_hosts'],
                'total_vulns': len(self.summary['vulnerabilities']),
                'global_risk_score': f"{self.summary['total_risk_score']:.2f}%"
            },
            'hosts': [h.to_dict() for h in self.results],
            'summary': {
                'total_ports': self.summary['total_ports'],
                'high_risk_ports': self.summary['high_risk_count'],
                'unique_ports': list(self.summary['unique_ports'].keys()),
                'top_5_ports': [{'port': p, 'count': c} for p, c in top_ports],
                'countries': self.summary['countries'],
                'vulnerabilities': list(self.summary['vulnerabilities'])
            }
        }
        with open(f"{output_dir}/audit_report.json", 'w') as f:
            json.dump(serializable, f, indent=2, default=str)

    def _create_map(self, output_dir: str):
        """
        Generate an interactive Folium map with GPS-pinned assets.
        High-risk hosts appear in red, others in blue.
        """
        if not self.raw_coords:
            m = folium.Map(location=[20, 0], zoom_start=2, tiles="OpenStreetMap")
            folium.Marker([20, 0], popup="No geolocation data available").add_to(m)
            m.save(f"{output_dir}/exposure_map.html")
            return

        avg_lat = sum(h.latitude for h in self.raw_coords) / len(self.raw_coords)
        avg_lon = sum(h.longitude for h in self.raw_coords) / len(self.raw_coords)

        m = folium.Map(location=[avg_lat, avg_lon], zoom_start=3, tiles="CartoDB dark_matter")
        cluster = MarkerCluster().add_to(m)

        for host in self.raw_coords:
            popup_text = f"""
            <b>IP:</b> {host.ip}<br>
            <b>Location:</b> {host.city}, {host.country}<br>
            <b>Organization:</b> {host.org}<br>
            <b>Open Ports:</b> {len(host.ports)}<br>
            <b>High Risk:</b> {len(host.high_risk_ports)}
            """
            color = 'red' if host.high_risk_ports else 'blue'
            folium.Marker(
                location=[host.latitude, host.longitude],
                popup=folium.Popup(popup_text, max_width=300),
                icon=folium.Icon(color=color, icon='shield', prefix='fa')
            ).add_to(cluster)

        m.save(f"{output_dir}/exposure_map.html")


# -----------------------------------------------------------------------------
# 8. MAIN EXECUTION ENTRY POINT
# -----------------------------------------------------------------------------
def main():
    """
    Parse command-line arguments and initiate the Terminus engine.

    Usage Examples:
      python terminus.py -d example.com -l 100
      python terminus.py -t 192.168.1.0/24 -o ./results/
      python terminus.py --debug
    """
    # Show the animated startup splash screen
    show_startup_splash()

    parser = argparse.ArgumentParser(
        description="Terminus v3.5 - Internet Exposure Attack Surface Framework",
        epilog="Developed by MojithaR 🎃🥷 | https://github.com/MojithaR/shodan-audit-tool"
    )

    parser.add_argument(
        "-t", "--target",
        type=str,
        help="Target domain, IP address, or CIDR range (e.g., example.com, 8.8.8.8, 192.168.1.0/24)"
    )
    parser.add_argument(
        "-d", "--domain",
        type=str,
        help="Alias for --target (for backward compatibility)"
    )
    parser.add_argument(
        "-l", "--limit",
        type=int,
        default=50,
        help="Maximum number of hosts to fetch (default: 50)"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="./audit_report",
        help="Directory to save reports (default: ./audit_report)"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug logging"
    )

    args = parser.parse_args()

    # Determine the target
    target = args.target or args.domain
    if not target:
        print(f"{TerminusColor.GREEN_BRIGHT}{SYM_ACTION} Terminus v3.5 Interactive Mode")
        target = input(f"{SYM_ACTION} Enter target (domain/IP/CIDR): ").strip()
        if not target:
            print(f"{TerminusColor.RED_CRITICAL}{SYM_CRITICAL} No target provided. Exiting.")
            return

    # Load API Key from .env file
    load_dotenv()
    api_key = os.getenv("SHODAN_API_KEY")

    if not api_key:
        print(f"{TerminusColor.RED_CRITICAL}{SYM_CRITICAL} SHODAN_API_KEY not found in .env file.")
        print(f"{SYM_ACTION} Create a .env file with: SHODAN_API_KEY=YOUR_KEY_HERE")
        return

    # Initialize and run
    engine = TerminusEngine(api_key, debug=args.debug)
    engine.run(target, limit=args.limit)

    if engine.results:
        engine.generate_reports(output_dir=args.output)
    else:
        print(f"{TerminusColor.RED_CRITICAL}{SYM_CRITICAL} No assets found. Exiting.")


if __name__ == "__main__":
    main()