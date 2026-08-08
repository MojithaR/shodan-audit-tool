#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  ███████╗██╗  ██╗ ██████╗ ██████╗  █████╗ ███╗   ██╗          ║
║  ██╔════╝██║  ██║██╔═══██╗██╔══██╗██╔══██╗████╗  ██║          ║
║  ███████╗███████║██║   ██║██║  ██║███████║██╔██╗ ██║          ║
║  ╚════██║██╔══██║██║   ██║██║  ██║██╔══██║██║╚██╗██║          ║
║  ███████║██║  ██║╚██████╔╝██████╔╝██║  ██║██║ ╚████║          ║
║  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝          ║
║      Internet Exposure Audit Tool - v2.0 (Cyber Edition)       ║
║            Shodan-Powered Attack Surface Mapper                ║
║                  Developed by: MojithaR 🚀                    ║
║                  GitHub: MojithaR/shodan-audit-tool            ║
╚══════════════════════════════════════════════════════════════════╝
"""

# ============================================
# DEVELOPER CREDENTIALS
# ============================================
__author__ = "MojithaR"
__github__ = "https://github.com/MojithaR/shodan-audit-tool"
__version__ = "2.0.0"

import shodan
import json
import os
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict

# Third-party imports
import pandas as pd
import folium
from folium.plugins import MarkerCluster
from prettytable import PrettyTable
from tqdm import tqdm
from dotenv import load_dotenv
from colorama import init, Fore, Style

# Initialize Colorama for Windows CMD colors
init(autoreset=True)

# ============================================
# 1. ENVIRONMENT & LOGGING SETUP
# ============================================
load_dotenv()

# Configure logging for debugging (saved to file)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('audit_debug.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ============================================
# 2. DATA CLASS (Structured Host Info)
# ============================================
@dataclass
class HostInfo:
    """Beautifully structured data container for each discovered host."""
    ip: str
    country: str
    city: str
    latitude: float
    longitude: float
    org: str
    os: str
    ports: List[int]
    high_risk_ports: List[int]
    vulnerabilities: List[str]
    services: List[Dict]
    last_update: str

    def to_dict(self) -> Dict:
        return asdict(self)


# ============================================
# 3. CORE AUDITOR ENGINE
# ============================================
class CyberAuditor:
    """
    Advanced Internet Exposure Auditor using Shodan API.
    Features: Multi-threading, Retry logic, Bulletproof error handling.
    Developed by: MojithaR
    """

    # Cyber-themed high-risk port mapping
    HIGH_RISK_MAP = {
        21: "💀 FTP (Anonymous)",
        22: "💀 SSH (Brute Force)",
        23: "💀 Telnet (Plaintext)",
        80: "⚠️ HTTP (Outdated)",
        443: "⚠️ HTTPS (SSL/TLS issues)",
        3389: "💀 RDP (BlueKeep/DC)",
        5900: "💀 VNC (Unauth)",
        27017: "💀 MongoDB (Data Leak)",
        6379: "💀 Redis (Unauth)",
        9200: "💀 Elasticsearch (Leak)",
        1433: "💀 MSSQL (Slammer)",
        3306: "💀 MySQL (Brute)",
        25: "⚠️ SMTP (Open Relay)",
        110: "⚠️ POP3",
        53: "⚠️ DNS (Amplification)",
        161: "⚠️ SNMP (Community Strings)",
        445: "💀 SMB (EternalBlue)",
        139: "💀 NetBIOS",
    }

    def __init__(self, api_key: str):
        self.api = shodan.Shodan(api_key)
        self.results: List[HostInfo] = []
        self.summary = {
            "total_hosts": 0,
            "total_ports": 0,
            "high_risk_count": 0,
            "vulnerabilities": set(),
            "countries": {}
        }
        # Store raw data for map generation
        self.raw_coords = []

    def _safe_get_vulns(self, host_data: Any) -> Dict:
        """
        🛡️ BULLETPROOF VULN PARSER: Fixes the 'list' vs 'dict' Shodan bug.
        """
        vulns = host_data.get('vulns', {})
        if isinstance(vulns, list):
            # If it's an empty list or malformed, return an empty dict
            return {}
        if not isinstance(vulns, dict):
            return {}
        return vulns

    def _retry_fetch(self, ip: str, retries: int = 2) -> Optional[Dict]:
        """Fetch host details with automatic retry on failure."""
        for attempt in range(retries):
            try:
                return self.api.host(ip)
            except shodan.APIError as e:
                if "rate" in str(e).lower() or "limit" in str(e).lower():
                    logger.warning(f"Rate limit hit for {ip}. Sleeping 2s...")
                    time.sleep(2)
                    continue
                logger.error(f"Shodan API error for {ip}: {e}")
                return None
            except Exception as e:
                logger.error(f"Unexpected error for {ip}: {e}")
                return None
        return None

    def fetch_host_details(self, ip: str) -> Optional[HostInfo]:
        """Fetch and parse details for a single IP with full error handling."""
        host = self._retry_fetch(ip)
        if not host:
            return None

        try:
            ports = host.get('ports', [])
            
            # 🛡️ THE FIX: Safe vulnerability parsing
            vulns = self._safe_get_vulns(host)
            vuln_list = list(vulns.keys())

            # Identify high-risk ports
            high_risk = [p for p in ports if p in self.HIGH_RISK_MAP]

            # Build services list
            services = []
            for item in host.get('data', []):
                services.append({
                    'port': item.get('port'),
                    'product': item.get('product', 'Unknown'),
                    'version': item.get('version', ''),
                    'banner': item.get('data', '')[:150]
                })

            # Create structured HostInfo object
            host_info = HostInfo(
                ip=ip,
                country=host.get('country_name', 'Unknown'),
                city=host.get('city', 'Unknown'),
                latitude=host.get('latitude', 0.0),
                longitude=host.get('longitude', 0.0),
                org=host.get('org', 'Unknown'),
                os=host.get('os', 'Unknown'),
                ports=ports,
                high_risk_ports=high_risk,
                vulnerabilities=vuln_list,
                services=services,
                last_update=host.get('last_update', '')
            )

            # Update global summary stats
            self.summary['total_ports'] += len(ports)
            self.summary['high_risk_count'] += len(high_risk)
            self.summary['countries'][host_info.country] = self.summary['countries'].get(host_info.country, 0) + 1
            self.summary['vulnerabilities'].update(vuln_list)
            
            # Store coordinates for map if they exist
            if host_info.latitude and host_info.longitude:
                self.raw_coords.append(host_info)

            return host_info

        except Exception as e:
            logger.error(f"Failed to parse host {ip}: {e}")
            return None

    def run_audit(self, domain: str, limit: int = 50) -> List[HostInfo]:
        """
        Main orchestration: Search domain -> Multi-threaded fetch -> Aggregate results.
        """
        print(f"{Fore.CYAN}[*] Scanning domain: {Fore.YELLOW}{domain}")
        
        # 1. Search Shodan
        try:
            query = f'hostname:{domain}'
            search_results = self.api.search(query, limit=limit)
            total_found = search_results['total']
            ips = [m['ip_str'] for m in search_results['matches']]
            print(f"{Fore.GREEN}[+] Found {total_found} hosts. Fetching details for {len(ips)} IPs...")
        except shodan.APIError as e:
            print(f"{Fore.RED}[!] Search failed: {e}")
            return []

        # 2. Multi-threaded fetching with a Progress Bar
        results_list = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Submit all tasks
            future_to_ip = {executor.submit(self.fetch_host_details, ip): ip for ip in ips}
            
            # Process with tqdm progress bar
            with tqdm(total=len(ips), desc=f"{Fore.MAGENTA}Hacking the mainframe", unit="IP") as pbar:
                for future in as_completed(future_to_ip):
                    result = future.result()
                    if result:
                        results_list.append(result)
                    pbar.update(1)

        self.results = results_list
        self.summary['total_hosts'] = len(results_list)
        print(f"{Fore.GREEN}[+] Successfully audited {len(results_list)} live hosts.")
        return results_list

    # ============================================
    # 4. REPORT GENERATORS (CSV, JSON, MAP, TERMINAL)
    # ============================================
    def generate_reports(self, output_dir: str = "./audit_report"):
        """Generate all outputs: CSV, JSON, Map, and Terminal Summary."""
        os.makedirs(output_dir, exist_ok=True)
        
        self._print_terminal_banner()
        self._export_csv(output_dir)
        self._export_json(output_dir)
        self._create_map(output_dir)
        
        print(f"\n{Fore.GREEN}✅ All reports generated successfully!")
        print(f"{Fore.CYAN}📁 Output folder: {output_dir}")
        print(f"{Fore.CYAN}📄 CSV/JSON: Ready for Excel/APIs")
        print(f"{Fore.CYAN}🗺️  Map: Open 'exposure_map.html' in your browser")
        print(f"\n{Fore.MAGENTA}🚀 Developed with ❤️ by MojithaR")
        print(f"{Fore.MAGENTA}🔗 GitHub: https://github.com/MojithaR/shodan-audit-tool")

    def _print_terminal_banner(self):
        """Cyber-themed terminal output with PrettyTable."""
        print("\n" + "="*80)
        print(f"{Fore.CYAN}        🌐 CYBER EXPOSURE REPORT")
        print(f"{Fore.CYAN}        Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}        Developer: {Fore.MAGENTA}MojithaR")
        print("="*80)
        
        # Summary Cards
        print(f"{Fore.YELLOW}┌─────────────┬──────────────────────────────────────────┐")
        print(f"{Fore.YELLOW}│ {Fore.WHITE}Metric       │ {Fore.WHITE}Value                                    │")
        print(f"{Fore.YELLOW}├─────────────┼──────────────────────────────────────────┤")
        print(f"{Fore.YELLOW}│ {Fore.GREEN}Total Hosts  │ {Fore.WHITE}{self.summary['total_hosts']:<40} │")
        print(f"{Fore.YELLOW}│ {Fore.GREEN}Open Ports   │ {Fore.WHITE}{self.summary['total_ports']:<40} │")
        print(f"{Fore.YELLOW}│ {Fore.RED}High-Risk    │ {Fore.WHITE}{self.summary['high_risk_count']:<40} │")
        print(f"{Fore.YELLOW}│ {Fore.RED}CVEs Found   │ {Fore.WHITE}{len(self.summary['vulnerabilities']):<40} │")
        print(f"{Fore.YELLOW}└─────────────┴──────────────────────────────────────────┘")

        # Asset Table
        if self.results:
            table = PrettyTable()
            table.field_names = [f"{Fore.CYAN}IP", f"{Fore.CYAN}Country", f"{Fore.CYAN}Ports", f"{Fore.CYAN}High-Risk", f"{Fore.CYAN}CVEs"]
            table.align = "l"
            
            for h in self.results[:15]:
                cve_display = f"{Fore.RED}⚠️ {len(h.vulnerabilities)}" if h.vulnerabilities else f"{Fore.GREEN}✅ 0"
                high_display = f"{Fore.RED}{len(h.high_risk_ports)}" if h.high_risk_ports else f"{Fore.GREEN}0"
                table.add_row([
                    h.ip,
                    h.country,
                    len(h.ports),
                    high_display,
                    cve_display
                ])
            
            print(f"\n{Fore.YELLOW}📋 Top 15 Assets:")
            print(table)

            # Vulnerability highlight
            if self.summary['vulnerabilities']:
                print(f"\n{Fore.RED}🔴 CRITICAL VULNERABILITIES DETECTED:")
                for v in list(self.summary['vulnerabilities'])[:10]:
                    print(f"  • {Fore.WHITE}{v}")

    def _export_csv(self, output_dir: str):
        """Export structured data to CSV."""
        data = []
        for h in self.results:
            data.append({
                'IP': h.ip,
                'Country': h.country,
                'City': h.city,
                'Organization': h.org,
                'OS': h.os,
                'Ports_Open': len(h.ports),
                'High_Risk_Ports': ', '.join(map(str, h.high_risk_ports)),
                'Vulnerabilities': ', '.join(h.vulnerabilities),
                'Last_Updated': h.last_update
            })
        df = pd.DataFrame(data)
        df.to_csv(f"{output_dir}/audit_report.csv", index=False, encoding='utf-8-sig')
        logger.info(f"CSV saved to {output_dir}/audit_report.csv")

    def _export_json(self, output_dir: str):
        """Export raw structured data to JSON."""
        # Convert HostInfo objects to dicts
        serializable = {
            'metadata': {
                'generated': datetime.now().isoformat(),
                'total_hosts': self.summary['total_hosts'],
                'total_vulns': len(self.summary['vulnerabilities']),
                'developer': 'MojithaR',
                'github': 'https://github.com/MojithaR/shodan-audit-tool'
            },
            'hosts': [h.to_dict() for h in self.results],
            'summary': {
                'total_ports': self.summary['total_ports'],
                'high_risk_ports': self.summary['high_risk_count'],
                'countries': self.summary['countries'],
                'vulnerabilities': list(self.summary['vulnerabilities'])
            }
        }
        with open(f"{output_dir}/audit_report.json", 'w') as f:
            json.dump(serializable, f, indent=2, default=str)
        logger.info(f"JSON saved to {output_dir}/audit_report.json")

    def _create_map(self, output_dir: str):
        """Generate a beautiful interactive map with actual GPS coordinates."""
        if not self.raw_coords:
            print(f"{Fore.YELLOW}[!] No GPS coordinates found. Creating generic map.")
            m = folium.Map(location=[20, 0], zoom_start=2, tiles="OpenStreetMap")
            folium.Marker([20, 0], popup="No geolocation data available").add_to(m)
            m.save(f"{output_dir}/exposure_map.html")
            return

        # Center map on average coordinates
        avg_lat = sum(h.latitude for h in self.raw_coords) / len(self.raw_coords)
        avg_lon = sum(h.longitude for h in self.raw_coords) / len(self.raw_coords)
        
        m = folium.Map(location=[avg_lat, avg_lon], zoom_start=3, tiles="CartoDB dark_matter")
        
        # Use MarkerCluster to handle many pins cleanly
        cluster = MarkerCluster().add_to(m)
        
        for host in self.raw_coords:
            popup_text = f"""
            <b>IP:</b> {host.ip}<br>
            <b>Location:</b> {host.city}, {host.country}<br>
            <b>Organization:</b> {host.org}<br>
            <b>Open Ports:</b> {len(host.ports)}<br>
            <b>High Risk:</b> {len(host.high_risk_ports)}
            """
            # Color based on risk
            color = 'red' if host.high_risk_ports else 'blue'
            folium.Marker(
                location=[host.latitude, host.longitude],
                popup=folium.Popup(popup_text, max_width=300),
                icon=folium.Icon(color=color, icon='shield', prefix='fa')
            ).add_to(cluster)
        
        m.save(f"{output_dir}/exposure_map.html")
        logger.info(f"Map saved to {output_dir}/exposure_map.html")


# ============================================
# 5. MAIN EXECUTION
# ============================================
def main():
    # Print Cyber Banner
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗
{Fore.CYAN}║  {Fore.GREEN}███████╗██╗  ██╗ ██████╗ ██████╗  █████╗ ███╗   ██╗{Fore.CYAN}          ║
{Fore.CYAN}║  {Fore.GREEN}██╔════╝██║  ██║██╔═══██╗██╔══██╗██╔══██╗████╗  ██║{Fore.CYAN}          ║
{Fore.CYAN}║  {Fore.GREEN}███████╗███████║██║   ██║██║  ██║███████║██╔██╗ ██║{Fore.CYAN}          ║
{Fore.CYAN}║  {Fore.GREEN}╚════██║██╔══██║██║   ██║██║  ██║██╔══██║██║╚██╗██║{Fore.CYAN}          ║
{Fore.CYAN}║  {Fore.GREEN}███████║██║  ██║╚██████╔╝██████╔╝██║  ██║██║ ╚████║{Fore.CYAN}          ║
{Fore.CYAN}║  {Fore.GREEN}╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝{Fore.CYAN}          ║
{Fore.CYAN}║      {Fore.WHITE}Internet Exposure Audit Tool {Fore.YELLOW}v2.0{Fore.CYAN}                         ║
{Fore.CYAN}║         {Fore.MAGENTA}Shodan-Powered Attack Surface Mapper{Fore.CYAN}                          ║
{Fore.CYAN}║              Developed by: {Fore.MAGENTA}MojithaR 🚀{Fore.CYAN}                               ║
{Fore.CYAN}║              GitHub: {Fore.MAGENTA}MojithaR/shodan-audit-tool{Fore.CYAN}                      ║
{Fore.CYAN}╚══════════════════════════════════════════════════════════════════╝
    """)

    # Load API Key from .env
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        print(f"{Fore.RED}[!] CRITICAL: SHODAN_API_KEY not found in .env file!")
        print(f"{Fore.YELLOW}[*] Create a .env file with: SHODAN_API_KEY=EfoKLcb2zHhNjyxmsIeU95hRHOcLqxb8")
        return

    # Get target
    target = input(f"{Fore.CYAN}⚡ Enter target domain (e.g., example.com): {Fore.WHITE}").strip()
    if not target:
        print(f"{Fore.RED}[!] Invalid input.")
        return

    # Initialize and Run
    auditor = CyberAuditor(api_key)
    start_time = time.time()
    auditor.run_audit(target, limit=50)
    elapsed = time.time() - start_time

    if auditor.results:
        auditor.generate_reports()
        print(f"\n{Fore.GREEN}⏱️ Audit finished in {elapsed:.2f} seconds.")
        print(f"{Fore.GREEN}🔗 Check your GitHub repo and share your results!")
        print(f"{Fore.MAGENTA}🚀 Developed with ❤️ by MojithaR")
    else:
        print(f"\n{Fore.RED}[!] No exposed assets found. Try a different domain.")
        print(f"{Fore.MAGENTA}🚀 Developed with ❤️ by MojithaR")

if __name__ == "__main__":
    main()