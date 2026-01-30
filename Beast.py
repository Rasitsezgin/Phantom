#!/usr/bin/env python3
"""
Log Attack Analyzer
Detect attack patterns in web server logs
Author: Security Research Team
License: MIT
"""

import re
import argparse
from collections import Counter, defaultdict
from datetime import datetime
from typing import List, Dict, Tuple
from dataclasses import dataclass, asdict
import json

@dataclass
class Attack:
    """Attack detection result"""
    timestamp: str
    ip: str
    attack_type: str
    severity: str
    payload: str
    url: str
    user_agent: str
    confidence: str

class LogAttackAnalyzer:
    """Analyze web logs for attack patterns"""
    
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.attacks: List[Attack] = []
        self.ip_requests: Counter = Counter()
        self.suspicious_ips: Dict[str, List[str]] = defaultdict(list)
        
        # Attack patterns
        self.patterns = {
            'SQL Injection': [
                r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
                r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
                r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
                r"((\%27)|(\'))union",
                r"exec(\s|\+)+(s|x)p\w+",
                r"UNION.*SELECT",
                r"SELECT.*FROM.*WHERE",
                r"INSERT.*INTO.*VALUES",
                r"DELETE.*FROM",
                r"DROP.*TABLE",
                r"UPDATE.*SET",
                r"' or '1'='1",
                r"' or 1=1--",
                r"admin' --",
                r"' UNION SELECT NULL",
                r"BENCHMARK\(",
                r"SLEEP\(",
                r"WAITFOR DELAY",
            ],
            'XSS': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"onerror\s*=",
                r"onload\s*=",
                r"<img[^>]+src",
                r"<iframe",
                r"<svg.*onload",
                r"alert\(",
                r"prompt\(",
                r"confirm\(",
                r"document\.cookie",
                r"<script>",
                r"eval\(",
                r"expression\(",
            ],
            'Path Traversal': [
                r"\.\./",
                r"\.\.\\",
                r"%2e%2e/",
                r"%2e%2e\\",
                r"\.\.%2f",
                r"\.\.%5c",
                r"/etc/passwd",
                r"/etc/shadow",
                r"c:\\windows",
                r"c:\\boot.ini",
            ],
            'Command Injection': [
                r";\s*ls\s",
                r";\s*cat\s",
                r";\s*wget\s",
                r";\s*curl\s",
                r"\|.*\|",
                r"`.*`",
                r"\$\(.*\)",
                r"&&",
                r";\s*rm\s",
                r";\s*whoami",
                r";\s*id\s",
                r"/bin/bash",
                r"/bin/sh",
            ],
            'LDAP Injection': [
                r"\*\)\(",
                r"\(\|",
                r"admin\*",
                r"\)\(\|",
            ],
            'XXE': [
                r"<!ENTITY",
                r"SYSTEM\s+\"file:",
                r"<!DOCTYPE.*\[",
            ],
            'SSRF': [
                r"localhost",
                r"127\.0\.0\.1",
                r"0\.0\.0\.0",
                r"169\.254\.",
                r"192\.168\.",
                r"10\.\d+\.",
                r"172\.(1[6-9]|2[0-9]|3[01])\.",
                r"file://",
                r"dict://",
                r"gopher://",
            ],
            'LFI/RFI': [
                r"php://input",
                r"php://filter",
                r"expect://",
                r"data://",
                r"file:///",
                r"\?.*=http://",
                r"\?.*=https://",
            ],
        }
        
        # Suspicious user agents
        self.suspicious_agents = [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'metasploit',
            'burp', 'zap', 'w3af', 'acunetix', 'nessus',
            'python-requests', 'curl', 'wget', 'scrapy',
        ]
        
    def parse_log_line(self, line: str) -> Dict:
        """Parse Apache/Nginx log line"""
        # Common Log Format (CLF) pattern
        # IP - - [timestamp] "METHOD /path HTTP/1.1" status size "referer" "user-agent"
        pattern = r'(\d+\.\d+\.\d+\.\d+).*?\[(.*?)\]\s+"(\w+)\s+(.*?)\s+HTTP/.*?"\s+(\d+)\s+(\d+)\s+"(.*?)"\s+"(.*?)"'
        
        match = re.search(pattern, line)
        if match:
            return {
                'ip': match.group(1),
                'timestamp': match.group(2),
                'method': match.group(3),
                'url': match.group(4),
                'status': int(match.group(5)),
                'size': match.group(6),
                'referer': match.group(7),
                'user_agent': match.group(8),
                'raw': line
            }
        return None
        
    def detect_attack_pattern(self, text: str) -> List[Tuple[str, str]]:
        """Detect attack patterns in text"""
        detected = []
        
        for attack_type, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    detected.append((attack_type, pattern))
                    break  # One match per attack type is enough
                    
        return detected
        
    def check_suspicious_ua(self, user_agent: str) -> bool:
        """Check if user agent is suspicious"""
        ua_lower = user_agent.lower()
        return any(sus in ua_lower for sus in self.suspicious_agents)
        
    def detect_brute_force(self, threshold: int = 100) -> List[str]:
        """Detect potential brute force attacks"""
        suspicious = []
        for ip, count in self.ip_requests.items():
            if count > threshold:
                suspicious.append(f"{ip}: {count} requests")
        return suspicious
        
    def analyze_logs(self):
        """Main log analysis function"""
        print(f"\n{'='*60}")
        print(f"Log Attack Analysis")
        print(f"Log File: {self.log_file}")
        print(f"{'='*60}\n")
        
        line_count = 0
        error_count = 0
        
        try:
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_count += 1
                    
                    # Parse log entry
                    entry = self.parse_log_line(line)
                    
                    if not entry:
                        error_count += 1
                        continue
                        
                    # Count requests per IP
                    self.ip_requests[entry['ip']] += 1
                    
                    # Check for attack patterns in URL
                    url_attacks = self.detect_attack_pattern(entry['url'])
                    
                    for attack_type, pattern in url_attacks:
                        # Determine severity
                        severity = 'High' if attack_type in ['SQL Injection', 'Command Injection', 'XXE'] else 'Medium'
                        
                        # Extract payload (the suspicious part)
                        payload = entry['url'][:200]
                        
                        attack = Attack(
                            timestamp=entry['timestamp'],
                            ip=entry['ip'],
                            attack_type=attack_type,
                            severity=severity,
                            payload=payload,
                            url=entry['url'],
                            user_agent=entry['user_agent'],
                            confidence='High'
                        )
                        
                        self.attacks.append(attack)
                        self.suspicious_ips[entry['ip']].append(attack_type)
                        
                        print(f"[!] {attack_type} detected from {entry['ip']}")
                        
                    # Check suspicious user agent
                    if self.check_suspicious_ua(entry['user_agent']):
                        attack = Attack(
                            timestamp=entry['timestamp'],
                            ip=entry['ip'],
                            attack_type='Suspicious User Agent',
                            severity='Low',
                            payload=entry['user_agent'],
                            url=entry['url'],
                            user_agent=entry['user_agent'],
                            confidence='Medium'
                        )
                        
                        self.attacks.append(attack)
                        self.suspicious_ips[entry['ip']].append('Scanner/Tool')
                        
                    # Check for 404/403 scanning
                    if entry['status'] in [404, 403]:
                        if any(word in entry['url'].lower() for word in ['.php', '.asp', '.jsp', 'admin', 'login', 'backup']):
                            attack = Attack(
                                timestamp=entry['timestamp'],
                                ip=entry['ip'],
                                attack_type='Directory/File Scanning',
                                severity='Low',
                                payload=entry['url'],
                                url=entry['url'],
                                user_agent=entry['user_agent'],
                                confidence='Medium'
                            )
                            self.attacks.append(attack)
                            
        except FileNotFoundError:
            print(f"[-] Error: Log file not found: {self.log_file}")
            return
        except Exception as e:
            print(f"[-] Error reading log file: {e}")
            return
            
        print(f"\n[*] Processed {line_count} log entries")
        print(f"[*] Parse errors: {error_count}")
        print(f"[*] Detected {len(self.attacks)} suspicious activities")
        
    def generate_statistics(self) -> Dict:
        """Generate attack statistics"""
        stats = {
            'total_attacks': len(self.attacks),
            'attack_types': Counter([a.attack_type for a in self.attacks]),
            'severity_breakdown': Counter([a.severity for a in self.attacks]),
            'top_attackers': self.ip_requests.most_common(10),
            'unique_ips': len(set(a.ip for a in self.attacks)),
        }
        
        # Brute force detection
        brute_force = self.detect_brute_force()
        stats['potential_brute_force'] = len(brute_force)
        stats['brute_force_ips'] = brute_force[:5]  # Top 5
        
        return stats
        
    def generate_report(self, format_type: str = 'json') -> str:
        """Generate analysis report"""
        if format_type == 'json':
            return self._generate_json()
        elif format_type == 'html':
            return self._generate_html()
        else:
            return self._generate_text()
            
    def _generate_json(self) -> str:
        """Generate JSON report"""
        stats = self.generate_statistics()
        
        # Convert Counter objects to dict
        stats['attack_types'] = dict(stats['attack_types'])
        stats['severity_breakdown'] = dict(stats['severity_breakdown'])
        
        report = {
            'log_file': self.log_file,
            'analysis_date': datetime.now().isoformat(),
            'statistics': stats,
            'attacks': [asdict(a) for a in self.attacks]
        }
        
        return json.dumps(report, indent=2)
        
    def _generate_html(self) -> str:
        """Generate HTML report with charts"""
        from html import escape
        
        stats = self.generate_statistics()
        
        # Prepare chart data
        attack_types_data = ', '.join([f"['{k}', {v}]" for k, v in stats['attack_types'].items()])
        severity_data = ', '.join([f"['{k}', {v}]" for k, v in stats['severity_breakdown'].items()])
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Log Attack Analysis Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
        h1 {{ color: #333; border-bottom: 3px solid #dc3545; padding-bottom: 10px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }}
        .stat-number {{ font-size: 36px; font-weight: bold; }}
        .stat-label {{ font-size: 14px; margin-top: 5px; opacity: 0.9; }}
        .charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin: 30px 0; }}
        .chart-container {{ background: #f8f9fa; padding: 20px; border-radius: 10px; }}
        .attack-list {{ margin-top: 30px; }}
        .attack {{ padding: 15px; margin: 10px 0; background: #f8f9fa; border-left: 4px solid; border-radius: 5px; }}
        .attack.High {{ border-color: #dc3545; }}
        .attack.Medium {{ border-color: #ffc107; }}
        .attack.Low {{ border-color: #17a2b8; }}
        .attack-header {{ font-weight: bold; margin-bottom: 5px; }}
        .attack-details {{ font-size: 14px; color: #666; }}
        code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px; font-size: 12px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #667eea; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Log Attack Analysis Report</h1>
        <p><strong>Log File:</strong> {escape(self.log_file)}</p>
        <p><strong>Analysis Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{stats['total_attacks']}</div>
                <div class="stat-label">Total Attacks Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['unique_ips']}</div>
                <div class="stat-label">Unique Attackers</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['potential_brute_force']}</div>
                <div class="stat-label">Potential Brute Force</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(stats['attack_types'])}</div>
                <div class="stat-label">Attack Types</div>
            </div>
        </div>
        
        <div class="charts">
            <div class="chart-container">
                <h3>Attack Types Distribution</h3>
                <canvas id="attackTypesChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Severity Breakdown</h3>
                <canvas id="severityChart"></canvas>
            </div>
        </div>
        
        <h2>Top Attackers</h2>
        <table>
            <tr>
                <th>IP Address</th>
                <th>Request Count</th>
                <th>Attack Types</th>
            </tr>
"""
        
        for ip, count in stats['top_attackers'][:10]:
            attack_types = ', '.join(set(self.suspicious_ips.get(ip, [])))
            html += f"""
            <tr>
                <td><code>{escape(ip)}</code></td>
                <td>{count}</td>
                <td>{escape(attack_types) if attack_types else 'N/A'}</td>
            </tr>
"""
        
        html += """
        </table>
        
        <h2>Attack Details (Latest 50)</h2>
        <div class="attack-list">
"""
        
        for attack in self.attacks[-50:]:
            html += f"""
            <div class="attack {attack.severity}">
                <div class="attack-header">{escape(attack.attack_type)} - {attack.severity}</div>
                <div class="attack-details">
                    <strong>Time:</strong> {escape(attack.timestamp)} |
                    <strong>IP:</strong> <code>{escape(attack.ip)}</code><br>
                    <strong>URL:</strong> <code>{escape(attack.url[:100])}</code><br>
                    <strong>User Agent:</strong> {escape(attack.user_agent[:80])}
                </div>
            </div>
"""
        
        html += f"""
        </div>
    </div>
    
    <script>
        // Attack Types Chart
        new Chart(document.getElementById('attackTypesChart'), {{
            type: 'doughnut',
            data: {{
                datasets: [{{
                    data: [{', '.join([str(v) for v in stats['attack_types'].values()])}],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#17a2b8', '#6610f2']
                }}],
                labels: [{', '.join([f"'{k}'" for k in stats['attack_types'].keys()])}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});
        
        // Severity Chart
        new Chart(document.getElementById('severityChart'), {{
            type: 'bar',
            data: {{
                labels: [{', '.join([f"'{k}'" for k in stats['severity_breakdown'].keys()])}],
                datasets: [{{
                    label: 'Count',
                    data: [{', '.join([str(v) for v in stats['severity_breakdown'].values()])}],
                    backgroundColor: ['#dc3545', '#ffc107', '#17a2b8']
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    y: {{ beginAtZero: true }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
        
        return html
        
    def _generate_text(self) -> str:
        """Generate text report"""
        stats = self.generate_statistics()
        
        report = f"""
{'='*60}
LOG ATTACK ANALYSIS REPORT
{'='*60}

Log File: {self.log_file}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY
Total Attacks Detected: {stats['total_attacks']}
Unique Attacker IPs: {stats['unique_ips']}
Potential Brute Force Attempts: {stats['potential_brute_force']}

ATTACK TYPES
"""
        
        for attack_type, count in stats['attack_types'].most_common():
            report += f"  {attack_type}: {count}\n"
            
        report += f"\nSEVERITY BREAKDOWN\n"
        for severity, count in stats['severity_breakdown'].items():
            report += f"  {severity}: {count}\n"
            
        report += f"\n{'='*60}\nTOP 10 ATTACKERS\n{'='*60}\n\n"
        
        for ip, count in stats['top_attackers'][:10]:
            attacks = ', '.join(set(self.suspicious_ips.get(ip, [])))
            report += f"{ip}: {count} requests\n"
            report += f"  Attack Types: {attacks if attacks else 'N/A'}\n\n"
            
        report += f"{'='*60}\nRECENT ATTACKS (Last 20)\n{'='*60}\n\n"
        
        for attack in self.attacks[-20:]:
            report += f"""
[{attack.severity}] {attack.attack_type}
Time: {attack.timestamp}
IP: {attack.ip}
URL: {attack.url[:80]}
User Agent: {attack.user_agent[:60]}
{'-'*60}
"""
        
        return report

def main():
    parser = argparse.ArgumentParser(
        description='Log Attack Pattern Analyzer',
        epilog='Example: python log_analyzer.py -l access.log -o report.html -f html'
    )
    parser.add_argument('-l', '--log', required=True, help='Log file to analyze')
    parser.add_argument('-o', '--output', default='log_report.json', help='Output file')
    parser.add_argument('-f', '--format', choices=['json', 'html', 'text'],
                       default='json', help='Output format')
    
    args = parser.parse_args()
    
    analyzer = LogAttackAnalyzer(args.log)
    analyzer.analyze_logs()
    
    # Generate report
    report = analyzer.generate_report(args.format)
    
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(report)
        
    print(f"\n{'='*60}")
    print(f"Analysis Complete!")
    print(f"Report saved to: {args.output}")
    print(f"{'='*60}\n")

if __name__ == '__main__':
    main()
