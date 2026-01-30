#!/usr/bin/env python3
"""
Mini WAF (Web Application Firewall) Engine
Request filtering and protection engine
Author: Security Research Team
License: MIT
"""

import re
import json
import argparse
from datetime import datetime
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict 
import time

@dataclass
class WafRule:
    """WAF rule definition"""
    id: str
    name: str
    pattern: str
    attack_type: str
    severity: str
    action: str  # BLOCK, LOG, CHALLENGE
    enabled: bool = True

@dataclass
class BlockedRequest:
    """Blocked request information"""
    timestamp: str
    ip: str
    method: str
    url: str
    rule_id: str
    rule_name: str
    attack_type: str
    matched_pattern: str
    action: str

class MiniWAF:
    """Lightweight Web Application Firewall Engine"""
    
    def __init__(self, config_file: str = None):
        self.rules: List[WafRule] = []
        self.blocked_requests: List[BlockedRequest] = []
        self.whitelist_ips: List[str] = []
        self.blacklist_ips: List[str] = []
        self.rate_limits: Dict[str, List[float]] = defaultdict(list)
        self.rate_limit_window = 60  # seconds
        self.rate_limit_max = 100  # requests per window
        
        if config_file:
            self.load_config(config_file)
        else:
            self._load_default_rules()
            
    def _load_default_rules(self):
        """Load default WAF rules"""
        default_rules = [
            # SQL Injection Rules
            WafRule(
                id="SQLI-001",
                name="SQL Injection - Union Attack",
                pattern=r"union.*select",
                attack_type="SQL Injection",
                severity="Critical",
                action="BLOCK"
            ),
            WafRule(
                id="SQLI-002",
                name="SQL Injection - OR 1=1",
                pattern=r"(\%27)|(\').*(\%6F)|(\').*or.*(\%27)|(\').*=.*(\%27)|(\').*=.*'",
                attack_type="SQL Injection",
                severity="Critical",
                action="BLOCK"
            ),
            WafRule(
                id="SQLI-003",
                name="SQL Injection - Comment",
                pattern=r"(\-\-)|(\#)|(/\*.*\*/)",
                attack_type="SQL Injection",
                severity="High",
                action="BLOCK"
            ),
            WafRule(
                id="SQLI-004",
                name="SQL Injection - Keywords",
                pattern=r"(select|insert|update|delete|drop|create|alter|exec|execute).*from",
                attack_type="SQL Injection",
                severity="Critical",
                action="BLOCK"
            ),
            WafRule(
                id="SQLI-005",
                name="SQL Injection - Sleep/Benchmark",
                pattern=r"(sleep|benchmark|waitfor)\s*\(",
                attack_type="SQL Injection",
                severity="Critical",
                action="BLOCK"
            ),
            
            # XSS Rules
            WafRule(
                id="XSS-001",
                name="XSS - Script Tag",
                pattern=r"<script[^>]*>.*?</script>",
                attack_type="Cross-Site Scripting",
                severity="High",
                action="BLOCK"
            ),
            WafRule(
                id="XSS-002",
                name="XSS - Event Handlers",
                pattern=r"on(load|error|click|mouse|focus|blur)\s*=",
                attack_type="Cross-Site Scripting",
                severity="High",
                action="BLOCK"
            ),
            WafRule(
                id="XSS-003",
                name="XSS - JavaScript Protocol",
                pattern=r"javascript:",
                attack_type="Cross-Site Scripting",
                severity="High",
                action="BLOCK"
            ),
            WafRule(
                id="XSS-004",
                name="XSS - IMG Tag",
                pattern=r"<img[^>]+src",
                attack_type="Cross-Site Scripting",
                severity="Medium",
                action="LOG"
            ),
            WafRule(
                id="XSS-005",
                name="XSS - SVG Tag",
                pattern=r"<svg.*onload",
                attack_type="Cross-Site Scripting",
                severity="High",
                action="BLOCK"
            ),
            
            # Path Traversal Rules
            WafRule(
                id="PATH-001",
                name="Path Traversal - Dot Dot Slash",
                pattern=r"\.\./|\.\\.\\|%2e%2e/|%2e%2e\\",
                attack_type="Path Traversal",
                severity="High",
                action="BLOCK"
            ),
            WafRule(
                id="PATH-002",
                name="Path Traversal - System Files",
                pattern=r"(/etc/passwd|/etc/shadow|c:\\windows|c:\\boot\.ini)",
                attack_type="Path Traversal",
                severity="Critical",
                action="BLOCK"
            ),
            
            # Command Injection Rules
            WafRule(
                id="CMD-001",
                name="Command Injection - Shell Commands",
                pattern=r"(;|\||`)\s*(ls|cat|wget|curl|nc|bash|sh|cmd|powershell)",
                attack_type="Command Injection",
                severity="Critical",
                action="BLOCK"
            ),
            WafRule(
                id="CMD-002",
                name="Command Injection - Command Substitution",
                pattern=r"(\$\(|\$\{|`)",
                attack_type="Command Injection",
                severity="High",
                action="BLOCK"
            ),
            
            # File Inclusion Rules
            WafRule(
                id="LFI-001",
                name="LFI - PHP Wrappers",
                pattern=r"php://(input|filter|expect|data)",
                attack_type="Local File Inclusion",
                severity="Critical",
                action="BLOCK"
            ),
            WafRule(
                id="RFI-001",
                name="RFI - Remote URL",
                pattern=r"\?.*=(https?|ftp)://",
                attack_type="Remote File Inclusion",
                severity="Critical",
                action="BLOCK"
            ),
            
            # SSRF Rules
            WafRule(
                id="SSRF-001",
                name="SSRF - Internal IPs",
                pattern=r"(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|192\.168\.|10\.\d+\.)",
                attack_type="Server-Side Request Forgery",
                severity="High",
                action="BLOCK"
            ),
            
            # XXE Rules
            WafRule(
                id="XXE-001",
                name="XXE - Entity Declaration",
                pattern=r"<!ENTITY.*SYSTEM",
                attack_type="XML External Entity",
                severity="Critical",
                action="BLOCK"
            ),
            
            # Generic Attack Patterns
            WafRule(
                id="GEN-001",
                name="Null Byte Injection",
                pattern=r"%00|\\x00",
                attack_type="Null Byte Injection",
                severity="Medium",
                action="BLOCK"
            ),
            WafRule(
                id="GEN-002",
                name="LDAP Injection",
                pattern=r"\*\)\(|\(\||admin\*|\)\(\|",
                attack_type="LDAP Injection",
                severity="High",
                action="BLOCK"
            ),
        ]
        
        self.rules = default_rules
        
    def load_config(self, config_file: str):
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                
            # Load rules
            if 'rules' in config:
                self.rules = [WafRule(**rule) for rule in config['rules']]
                
            # Load whitelists/blacklists
            self.whitelist_ips = config.get('whitelist_ips', [])
            self.blacklist_ips = config.get('blacklist_ips', [])
            
            # Load rate limit settings
            self.rate_limit_window = config.get('rate_limit_window', 60)
            self.rate_limit_max = config.get('rate_limit_max', 100)
            
            print(f"[+] Loaded {len(self.rules)} rules from {config_file}")
            
        except Exception as e:
            print(f"[-] Error loading config: {e}")
            print(f"[*] Loading default rules instead")
            self._load_default_rules()
            
    def save_config(self, config_file: str):
        """Save configuration to JSON file"""
        config = {
            'rules': [asdict(rule) for rule in self.rules],
            'whitelist_ips': self.whitelist_ips,
            'blacklist_ips': self.blacklist_ips,
            'rate_limit_window': self.rate_limit_window,
            'rate_limit_max': self.rate_limit_max
        }
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
            
        print(f"[+] Configuration saved to {config_file}")
        
    def check_ip_blacklist(self, ip: str) -> bool:
        """Check if IP is blacklisted"""
        return ip in self.blacklist_ips
        
    def check_ip_whitelist(self, ip: str) -> bool:
        """Check if IP is whitelisted"""
        return ip in self.whitelist_ips
        
    def check_rate_limit(self, ip: str) -> Tuple[bool, int]:
        """Check rate limit for IP"""
        now = time.time()
        
        # Clean old entries
        self.rate_limits[ip] = [t for t in self.rate_limits[ip] 
                                if now - t < self.rate_limit_window]
        
        # Add current request
        self.rate_limits[ip].append(now)
        
        # Check limit
        request_count = len(self.rate_limits[ip])
        exceeded = request_count > self.rate_limit_max
        
        return exceeded, request_count
        
    def inspect_request(self, ip: str, method: str, url: str, 
                       headers: Dict = None, body: str = None) -> Tuple[bool, str, List[str]]:
        """
        Inspect HTTP request against WAF rules
        
        Returns:
            (allowed, action, matched_rules)
        """
        matched_rules = []
        
        # Check whitelist first
        if self.check_ip_whitelist(ip):
            return True, "ALLOW", []
            
        # Check blacklist
        if self.check_ip_blacklist(ip):
            self._log_block(ip, method, url, "IP-BLACKLIST", "IP Blacklisted", 
                          "IP Blacklist", "", "BLOCK")
            return False, "BLOCK", ["IP-BLACKLIST"]
            
        # Check rate limit
        exceeded, count = self.check_rate_limit(ip)
        if exceeded:
            self._log_block(ip, method, url, "RATE-LIMIT", "Rate Limit Exceeded",
                          "Rate Limiting", f"{count} requests in {self.rate_limit_window}s", "BLOCK")
            return False, "BLOCK", ["RATE-LIMIT"]
            
        # Combine all request data
        request_data = f"{url} {body or ''}"
        if headers:
            request_data += " " + " ".join(headers.values())
            
        # Check against rules
        highest_action = "ALLOW"
        
        for rule in self.rules:
            if not rule.enabled:
                continue
                
            if re.search(rule.pattern, request_data, re.IGNORECASE):
                matched_rules.append(rule.id)
                
                # Log the match
                self._log_block(ip, method, url, rule.id, rule.name, 
                              rule.attack_type, rule.pattern, rule.action)
                
                # Determine action (BLOCK > CHALLENGE > LOG)
                if rule.action == "BLOCK":
                    highest_action = "BLOCK"
                elif rule.action == "CHALLENGE" and highest_action != "BLOCK":
                    highest_action = "CHALLENGE"
                    
        # Return result
        allowed = highest_action not in ["BLOCK", "CHALLENGE"]
        return allowed, highest_action, matched_rules
        
    def _log_block(self, ip: str, method: str, url: str, rule_id: str,
                   rule_name: str, attack_type: str, pattern: str, action: str):
        """Log blocked request"""
        blocked = BlockedRequest(
            timestamp=datetime.now().isoformat(),
            ip=ip,
            method=method,
            url=url,
            rule_id=rule_id,
            rule_name=rule_name,
            attack_type=attack_type,
            matched_pattern=pattern,
            action=action
        )
        
        self.blocked_requests.append(blocked)
        
        print(f"[{action}] {attack_type} from {ip} - Rule: {rule_id}")
        
    def get_statistics(self) -> Dict:
        """Get WAF statistics"""
        stats = {
            'total_blocked': len(self.blocked_requests),
            'rules_count': len(self.rules),
            'enabled_rules': sum(1 for r in self.rules if r.enabled),
            'blocked_by_type': {},
            'blocked_by_ip': {},
            'recent_blocks': []
        }
        
        # Count by attack type
        for req in self.blocked_requests:
            stats['blocked_by_type'][req.attack_type] = \
                stats['blocked_by_type'].get(req.attack_type, 0) + 1
            stats['blocked_by_ip'][req.ip] = \
                stats['blocked_by_ip'].get(req.ip, 0) + 1
                
        # Get recent blocks
        stats['recent_blocks'] = [asdict(b) for b in self.blocked_requests[-10:]]
        
        return stats
        
    def generate_report(self, format_type: str = 'json') -> str:
        """Generate WAF activity report"""
        if format_type == 'json':
            return self._generate_json_report()
        else:
            return self._generate_text_report()
            
    def _generate_json_report(self) -> str:
        """Generate JSON report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'statistics': self.get_statistics(),
            'rules': [asdict(r) for r in self.rules],
            'blocked_requests': [asdict(b) for b in self.blocked_requests]
        }
        return json.dumps(report, indent=2)
        
    def _generate_text_report(self) -> str:
        """Generate text report"""
        stats = self.get_statistics()
        
        report = f"""
{'='*60}
WAF ACTIVITY REPORT
{'='*60}

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

STATISTICS
Total Blocked Requests: {stats['total_blocked']}
Active Rules: {stats['enabled_rules']}/{stats['rules_count']}

BLOCKED BY ATTACK TYPE
"""
        
        for attack_type, count in sorted(stats['blocked_by_type'].items(), 
                                        key=lambda x: x[1], reverse=True):
            report += f"  {attack_type}: {count}\n"
            
        report += f"\nTOP BLOCKED IPs\n"
        
        for ip, count in sorted(stats['blocked_by_ip'].items(), 
                               key=lambda x: x[1], reverse=True)[:10]:
            report += f"  {ip}: {count} blocks\n"
            
        report += f"\n{'='*60}\nRECENT BLOCKS\n{'='*60}\n"
        
        for block in stats['recent_blocks']:
            report += f"""
Time: {block['timestamp']}
IP: {block['ip']}
URL: {block['url']}
Attack: {block['attack_type']}
Rule: {block['rule_id']} - {block['rule_name']}
Action: {block['action']}
{'-'*60}
"""
        
        return report

def main():
    parser = argparse.ArgumentParser(
        description='Mini WAF Engine',
        epilog='Example: python mini_waf.py --config waf_config.json --test'
    )
    parser.add_argument('--config', help='Configuration file (JSON)')
    parser.add_argument('--save-config', help='Save current config to file')
    parser.add_argument('--test', action='store_true', help='Run test cases')
    parser.add_argument('--report', help='Generate activity report')
    parser.add_argument('--format', choices=['json', 'text'], default='json',
                       help='Report format')
    
    args = parser.parse_args()
    
    # Initialize WAF
    waf = MiniWAF(config_file=args.config)
    
    if args.save_config:
        waf.save_config(args.save_config)
        return
        
    if args.test:
        print("\n[*] Running WAF tests...\n")
        
        # Test cases
        test_requests = [
            ("192.168.1.100", "GET", "/page?id=1' OR '1'='1", None, None),
            ("10.0.0.50", "GET", "/search?q=<script>alert('XSS')</script>", None, None),
            ("172.16.0.10", "GET", "/file?path=../../etc/passwd", None, None),
            ("8.8.8.8", "POST", "/api/exec", None, "cmd=ls; cat /etc/passwd"),
            ("1.2.3.4", "GET", "/test?url=http://evil.com", None, None),
        ]
        
        for ip, method, url, headers, body in test_requests:
            allowed, action, rules = waf.inspect_request(ip, method, url, headers, body)
            status = "✓ ALLOWED" if allowed else "✗ BLOCKED"
            print(f"{status} - {method} {url[:50]} (Action: {action})")
            
    if args.report:
        report = waf.generate_report(args.format)
        
        with open(args.report, 'w') as f:
            f.write(report)
            
        print(f"\n[+] Report saved to: {args.report}")
        
    # Interactive mode if no args
    if not any([args.save_config, args.test, args.report]):
        print("\nMini WAF Engine - Interactive Mode")
        print("Enter requests to test (format: IP METHOD URL)")
        print("Example: 192.168.1.1 GET /test?id=1")
        print("Type 'exit' to quit\n")
        
        while True:
            try:
                user_input = input("> ").strip()
                
                if user_input.lower() == 'exit':
                    break
                    
                if not user_input:
                    continue
                    
                parts = user_input.split(maxsplit=2)
                if len(parts) < 3:
                    print("Invalid format. Use: IP METHOD URL")
                    continue
                    
                ip, method, url = parts
                allowed, action, rules = waf.inspect_request(ip, method, url)
                
                if allowed:
                    print(f"✓ Request ALLOWED")
                else:
                    print(f"✗ Request {action}")
                    print(f"  Matched rules: {', '.join(rules)}")
                    
            except KeyboardInterrupt:
                print("\n\nExiting...")
                break
            except Exception as e:
                print(f"Error: {e}")

if __name__ == '__main__':
    main()
