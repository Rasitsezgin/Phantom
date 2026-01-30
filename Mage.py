#!/usr/bin/env python3
"""
Smart Subdomain Enumerator
Efficient subdomain discovery with DNS resolution and HTTP status checking
Author: Security Research Team
License: MIT
"""

import asyncio
import aiodns
import aiohttp
import argparse
import csv
from typing import List, Set, Dict
from dataclasses import dataclass, asdict
from datetime import datetime
import socket

@dataclass
class Subdomain:
    """Subdomain information"""
    subdomain: str
    ip_addresses: List[str]
    http_status: int
    https_status: int
    title: str
    server: str
    cdn: str
    timestamp: str

class SubdomainEnumerator:
    """Smart subdomain enumeration with multiple discovery methods"""
    
    def __init__(self, domain: str, wordlist: str = None, threads: int = 50):
        self.domain = domain
        self.wordlist = wordlist or self._get_default_wordlist()
        self.threads = threads
        self.found_subdomains: List[Subdomain] = []
        self.resolver = None
        self.session = None
        
    def _get_default_wordlist(self) -> List[str]:
        """Get default subdomain wordlist"""
        return [
            # Common subdomains
            'www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2', 'webmail',
            'admin', 'portal', 'blog', 'shop', 'store', 'api', 'dev', 'stage',
            'staging', 'test', 'demo', 'beta', 'alpha', 'cdn', 'assets',
            'static', 'media', 'images', 'img', 'js', 'css', 'files',
            'download', 'uploads', 'vpn', 'remote', 'ssh', 'sftp',
            
            # Cloud/Infrastructure
            'cloud', 'aws', 'azure', 'gcp', 'jenkins', 'gitlab', 'github',
            'bitbucket', 'jira', 'confluence', 'docker', 'kubernetes', 'k8s',
            
            # Services
            'mail1', 'mail2', 'email', 'newsletter', 'support', 'help',
            'helpdesk', 'status', 'monitor', 'monitoring', 'metrics',
            'analytics', 'tracking', 'logs', 'syslog',
            
            # Environments
            'prod', 'production', 'development', 'uat', 'qa', 'preprod',
            'sandbox', 'preview', 'canary',
            
            # Regional
            'us', 'eu', 'asia', 'au', 'uk', 'de', 'fr', 'jp', 'cn',
            'us-east', 'us-west', 'eu-west', 'eu-central',
            
            # Web applications
            'app', 'mobile', 'm', 'web', 'www1', 'www2', 'secure',
            'login', 'signin', 'signup', 'register', 'dashboard',
            'panel', 'control', 'cpanel', 'whm', 'phpmyadmin',
            
            # Database
            'db', 'database', 'mysql', 'postgres', 'mongodb', 'redis',
            'sql', 'data', 'backup', 'backups',
            
            # Communication
            'chat', 'irc', 'slack', 'teams', 'meet', 'video', 'call',
            
            # Marketing
            'marketing', 'promo', 'campaign', 'ads', 'ad',
            
            # Mobile
            'ios', 'android', 'mobile-api',
            
            # Legacy
            'old', 'legacy', 'archive', 'archives', 'backup',
            
            # Internal
            'internal', 'intranet', 'corp', 'corporate',
            
            # Other common
            'home', 'main', 'news', 'forum', 'forums', 'community',
            'docs', 'documentation', 'wiki', 'kb', 'faq',
        ]
        
    async def initialize(self):
        """Initialize async resources"""
        self.resolver = aiodns.DNSResolver(timeout=3.0)
        connector = aiohttp.TCPConnector(limit=self.threads, ssl=False)
        timeout = aiohttp.ClientTimeout(total=5)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        
    async def close(self):
        """Close async resources"""
        if self.session:
            await self.session.close()
            
    async def resolve_dns(self, subdomain: str) -> List[str]:
        """Resolve subdomain to IP addresses"""
        try:
            result = await self.resolver.query(subdomain, 'A')
            return [r.host for r in result]
        except Exception:
            return []
            
    async def check_http_status(self, url: str) -> tuple:
        """Check HTTP status and extract info"""
        try:
            async with self.session.get(url, allow_redirects=True) as response:
                # Extract title
                title = ''
                try:
                    text = await response.text()
                    import re
                    title_match = re.search(r'<title>(.*?)</title>', text, re.IGNORECASE)
                    if title_match:
                        title = title_match.group(1).strip()[:100]
                except:
                    pass
                    
                server = response.headers.get('Server', '')
                
                return response.status, title, server
        except Exception:
            return 0, '', ''
            
    def detect_cdn(self, headers: dict, ips: List[str]) -> str:
        """Detect CDN usage"""
        cdn_indicators = {
            'Cloudflare': ['cloudflare', 'cf-ray'],
            'Akamai': ['akamai'],
            'Fastly': ['fastly'],
            'Amazon CloudFront': ['cloudfront'],
            'Incapsula': ['incapsula'],
            'MaxCDN': ['maxcdn'],
            'KeyCDN': ['keycdn'],
        }
        
        # Check headers
        for cdn, indicators in cdn_indicators.items():
            for header, value in headers.items():
                for indicator in indicators:
                    if indicator.lower() in header.lower() or indicator.lower() in str(value).lower():
                        return cdn
                        
        # Check IPs (basic check)
        # This would need a proper IP range database in production
        if ips:
            # Cloudflare IP ranges (simplified)
            cloudflare_ranges = ['104.', '172.']
            for ip in ips:
                for cf_range in cloudflare_ranges:
                    if ip.startswith(cf_range):
                        return 'Cloudflare (possible)'
                        
        return 'None detected'
        
    async def enumerate_subdomain(self, prefix: str) -> bool:
        """Try to enumerate a single subdomain"""
        subdomain = f"{prefix}.{self.domain}"
        
        # DNS resolution
        ips = await self.resolve_dns(subdomain)
        
        if not ips:
            return False
            
        print(f"[+] Found: {subdomain} -> {', '.join(ips)}")
        
        # Check HTTP/HTTPS
        http_status, http_title, http_server = await self.check_http_status(f"http://{subdomain}")
        https_status, https_title, https_server = await self.check_http_status(f"https://{subdomain}")
        
        title = https_title or http_title
        server = https_server or http_server
        
        # Detect CDN (simplified)
        cdn = 'Unknown'
        
        subdomain_info = Subdomain(
            subdomain=subdomain,
            ip_addresses=ips,
            http_status=http_status,
            https_status=https_status,
            title=title,
            server=server,
            cdn=cdn,
            timestamp=datetime.now().isoformat()
        )
        
        self.found_subdomains.append(subdomain_info)
        return True
        
    async def run_enumeration(self):
        """Run subdomain enumeration"""
        print(f"\n{'='*60}")
        print(f"Subdomain Enumeration")
        print(f"Target Domain: {self.domain}")
        print(f"Wordlist Size: {len(self.wordlist)}")
        print(f"{'='*60}\n")
        
        # Create tasks
        tasks = []
        for prefix in self.wordlist:
            tasks.append(self.enumerate_subdomain(prefix))
            
        # Run with progress
        await asyncio.gather(*tasks)
        
        print(f"\n[*] Enumeration complete!")
        print(f"[*] Found {len(self.found_subdomains)} subdomains")
        
    def export_csv(self, filename: str):
        """Export results to CSV"""
        if not self.found_subdomains:
            print("[-] No subdomains found to export")
            return
            
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'subdomain', 'ip_addresses', 'http_status', 'https_status',
                'title', 'server', 'cdn', 'timestamp'
            ])
            writer.writeheader()
            
            for sub in self.found_subdomains:
                row = asdict(sub)
                row['ip_addresses'] = ', '.join(row['ip_addresses'])
                writer.writerow(row)
                
        print(f"[+] Results exported to: {filename}")
        
    def export_json(self, filename: str):
        """Export results to JSON"""
        import json
        
        if not self.found_subdomains:
            print("[-] No subdomains found to export")
            return
            
        data = {
            'domain': self.domain,
            'scan_date': datetime.now().isoformat(),
            'total_found': len(self.found_subdomains),
            'subdomains': [asdict(sub) for sub in self.found_subdomains]
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
            
        print(f"[+] Results exported to: {filename}")
        
    def print_summary(self):
        """Print enumeration summary"""
        print(f"\n{'='*60}")
        print(f"ENUMERATION SUMMARY")
        print(f"{'='*60}")
        print(f"Total Subdomains Found: {len(self.found_subdomains)}")
        
        # Count by HTTP status
        http_live = sum(1 for s in self.found_subdomains if s.http_status in [200, 301, 302])
        https_live = sum(1 for s in self.found_subdomains if s.https_status in [200, 301, 302])
        
        print(f"HTTP Accessible: {http_live}")
        print(f"HTTPS Accessible: {https_live}")
        print(f"{'='*60}\n")
        
        # Print table
        print(f"{'Subdomain':<40} {'IPs':<20} {'HTTP':<6} {'HTTPS':<6}")
        print(f"{'-'*75}")
        
        for sub in sorted(self.found_subdomains, key=lambda x: x.subdomain):
            ips = ', '.join(sub.ip_addresses[:2])
            if len(sub.ip_addresses) > 2:
                ips += '...'
            print(f"{sub.subdomain:<40} {ips:<20} {sub.http_status:<6} {sub.https_status:<6}")

async def main():
    parser = argparse.ArgumentParser(
        description='Smart Subdomain Enumerator',
        epilog='Example: python subdomain_enum.py -d example.com -w wordlist.txt -o results.csv'
    )
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist file')
    parser.add_argument('-o', '--output', default='subdomains.csv', help='Output file')
    parser.add_argument('-f', '--format', choices=['csv', 'json'], default='csv',
                       help='Output format')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Number of concurrent threads')
    
    args = parser.parse_args()
    
    # Load custom wordlist if provided
    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(wordlist)} entries from {args.wordlist}")
        except Exception as e:
            print(f"[-] Error loading wordlist: {e}")
            return
            
    enumerator = SubdomainEnumerator(
        domain=args.domain,
        wordlist=wordlist,
        threads=args.threads
    )
    
    try:
        await enumerator.initialize()
        await enumerator.run_enumeration()
        
        # Export results
        if args.format == 'csv':
            enumerator.export_csv(args.output)
        else:
            enumerator.export_json(args.output)
            
        # Print summary
        enumerator.print_summary()
        
    finally:
        await enumerator.close()

if __name__ == '__main__':
    asyncio.run(main())
