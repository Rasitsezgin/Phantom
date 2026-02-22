#!/usr/bin/env python3
"""
Advanced Web Vulnerability Scanner
Professional security assessment tool for bug bounty programs
"""

import asyncio
import aiohttp
import argparse
import html as html_lib
import json
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from datetime import datetime
from typing import List, Dict, Set
import re
from dataclasses import dataclass, asdict
import html

@dataclass
class Vulnerability:
    """Data class for vulnerability findings"""
    severity: str  # Critical, High, Medium, Low, Info
    type: str
    url: str
    parameter: str
    payload: str
    evidence: str
    confidence: str  # Confirmed, Probable, Possible
    remediation: str
    timestamp: str

class AdvancedWebScanner:
    """Professional web vulnerability scanner with OWASP Top 10 coverage"""
    
    def __init__(self, target: str, timeout: int = 10, threads: int = 10):
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.vulnerabilities: List[Vulnerability] = []
        self.tested_urls: Set[str] = set()
        self.session = None
        
        # XSS Payloads with context awareness
        self.xss_payloads = [
            # Basic reflection tests
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
            
            # DOM-based
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            
            # Filter bypass
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<img src=x onerror=alert`XSS`>",
            "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
            
            # Attribute injection
            "' autofocus onfocus=alert('XSS') x='",
            "\" autofocus onfocus=alert('XSS') x=\"",
            
            # Advanced polyglots
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//\\x3e",
        ]
        
        # SQL Injection payloads
        self.sqli_payloads = [
            # Error-based
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            
            # Time-based blind
            "' AND SLEEP(5)--",
            "' AND BENCHMARK(5000000,MD5('A'))--",
            "1' WAITFOR DELAY '0:0:5'--",
            
            # Union-based
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            
            # Boolean-based
            "' AND 1=1--",
            "' AND 1=2--",
            
            # Advanced
            "admin' OR '1'='1'--",
            "1' ORDER BY 1--",
            "1' GROUP BY 1--",
        ]
        
        # Open Redirect payloads
        self.redirect_payloads = [
            "//evil.com",
            "https://evil.com",
            "//google.com",
            "javascript:alert('XSS')",
            "/\\evil.com",
            "https:evil.com",
        ]
        
        # Common admin panels
        self.admin_paths = [
            "/admin", "/administrator", "/admin.php", "/admin/login",
            "/wp-admin", "/administrator.php", "/adminpanel",
            "/admin/index.php", "/admin/admin.php", "/login",
            "/admin/dashboard", "/controlpanel", "/cp",
            "/modcp", "/admincp", "/admin_area", "/panel",
        ]
        
        # Security headers to check
        self.security_headers = {
            'X-Frame-Options': 'Missing clickjacking protection',
            'X-Content-Type-Options': 'Missing MIME sniffing protection',
            'Strict-Transport-Security': 'Missing HSTS',
            'Content-Security-Policy': 'Missing CSP',
            'X-XSS-Protection': 'Missing XSS protection header',
            'Referrer-Policy': 'Missing referrer policy',
            'Permissions-Policy': 'Missing permissions policy',
        }
        
    async def initialize(self):
        """Initialize async session"""
        connector = aiohttp.TCPConnector(limit=self.threads)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        
    async def close(self):
        """Close async session"""
        if self.session:
            await self.session.close()
            
    def add_vulnerability(self, severity: str, vuln_type: str, url: str, 
                         parameter: str, payload: str, evidence: str, 
                         confidence: str, remediation: str):
        """Add a vulnerability to the findings list"""
        vuln = Vulnerability(
            severity=severity,
            type=vuln_type,
            url=url,
            parameter=parameter,
            payload=payload,
            evidence=evidence,
            confidence=confidence,
            remediation=remediation,
            timestamp=datetime.now().isoformat()
        )
        self.vulnerabilities.append(vuln)
        
    async def fetch(self, url: str, method: str = 'GET', data: dict = None) -> tuple:
        """Fetch URL with error handling"""
        try:
            if method == 'GET':
                async with self.session.get(url) as response:
                    text = await response.text()
                    return response.status, text, response.headers
            else:
                async with self.session.post(url, data=data) as response:
                    text = await response.text()
                    return response.status, text, response.headers
        except Exception as e:
            return None, None, None
            
    async def test_xss(self, url: str, params: dict):
        """Test for Cross-Site Scripting vulnerabilities"""
        print(f"[*] Testing XSS on: {url}")
        
        for param in params:
            for payload in self.xss_payloads:
                # Create test URL
                test_params = params.copy()
                test_params[param] = payload
                test_url = f"{url}?{urlencode(test_params)}"
                
                # Avoid duplicate tests
                if test_url in self.tested_urls:
                    continue
                self.tested_urls.add(test_url)
                
                # Fetch response
                status, response, headers = await self.fetch(test_url)
                if not response:
                    continue
                
                # Check for reflection - decode HTML entities first
                decoded_response = html.unescape(response)
                
                # Basic reflection check
                if payload in decoded_response or payload in response:
                    # Verify it's not just in comments or escaped
                    confidence = self._verify_xss_context(response, payload)
                    
                    if confidence != "False Positive":
                        self.add_vulnerability(
                            severity="High",
                            vuln_type="Cross-Site Scripting (XSS)",
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=f"Payload reflected in response. Status: {status}",
                            confidence=confidence,
                            remediation="Implement input validation and output encoding. Use Content-Security-Policy header."
                        )
                        print(f"[!] XSS Found: {param} = {payload[:50]}...")
                        break  # Move to next parameter
                        
    def _verify_xss_context(self, response: str, payload: str) -> str:
        """Verify XSS is in executable context"""
        # Check if payload is in HTML comments
        if f"<!--{payload}" in response or f"{payload}-->" in response:
            return "False Positive"
            
        # Check if properly escaped
        escaped_chars = ['&lt;', '&gt;', '&quot;', '&#', '\\x3c', '\\x3e']
        for esc in escaped_chars:
            if esc in response.lower():
                # Payload might be escaped
                return "Possible"
                
        # Check if in script context
        script_pattern = r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>'
        if re.search(script_pattern, response, re.IGNORECASE | re.DOTALL):
            return "Confirmed"
            
        # Check if in event handler
        event_pattern = r'on\w+\s*=\s*["\']?' + re.escape(payload)
        if re.search(event_pattern, response, re.IGNORECASE):
            return "Confirmed"
            
        return "Probable"
        
    async def test_sqli(self, url: str, params: dict):
        """Test for SQL Injection vulnerabilities"""
        print(f"[*] Testing SQLi on: {url}")
        
        for param in params:
            baseline_status = None
            baseline_time = None
            
            # Get baseline
            baseline_url = f"{url}?{urlencode(params)}"
            start = time.time()
            baseline_status, baseline_response, _ = await self.fetch(baseline_url)
            baseline_time = time.time() - start
            
            if not baseline_response:
                continue
            
            for payload in self.sqli_payloads:
                test_params = params.copy()
                test_params[param] = payload
                test_url = f"{url}?{urlencode(test_params)}"
                
                if test_url in self.tested_urls:
                    continue
                self.tested_urls.add(test_url)
                
                # Time-based detection
                start = time.time()
                status, response, headers = await self.fetch(test_url)
                elapsed = time.time() - start
                
                if not response:
                    continue
                
                # Error-based detection
                sql_errors = [
                    'sql syntax', 'mysql', 'sqlite', 'postgresql', 'oracle',
                    'warning: mysql', 'unclosed quotation', 'quoted string',
                    'syntax error', 'unterminated string', 'database error',
                    'db error', 'odbc', 'jdbc', 'microsoft ole db',
                ]
                
                response_lower = response.lower()
                for error in sql_errors:
                    if error in response_lower:
                        self.add_vulnerability(
                            severity="Critical",
                            vuln_type="SQL Injection (Error-based)",
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=f"SQL error message detected in response",
                            confidence="Confirmed",
                            remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL queries."
                        )
                        print(f"[!] SQLi Found (Error-based): {param} = {payload[:50]}...")
                        break
                
                # Time-based detection (>3 second delay)
                if 'SLEEP' in payload or 'WAITFOR' in payload or 'BENCHMARK' in payload:
                    if elapsed > 3 and baseline_time < 2:
                        self.add_vulnerability(
                            severity="Critical",
                            vuln_type="SQL Injection (Time-based Blind)",
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=f"Response time: {elapsed:.2f}s vs baseline: {baseline_time:.2f}s",
                            confidence="Probable",
                            remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL queries."
                        )
                        print(f"[!] SQLi Found (Time-based): {param} = {payload[:50]}...")
                        
    async def test_open_redirect(self, url: str, params: dict):
        """Test for Open Redirect vulnerabilities"""
        print(f"[*] Testing Open Redirect on: {url}")
        
        redirect_params = ['url', 'redirect', 'next', 'return', 'returnUrl', 
                          'redirect_url', 'go', 'target', 'rurl', 'dest', 
                          'destination', 'redir', 'redirect_uri', 'continue']
        
        for param in params:
            if param.lower() not in redirect_params:
                continue
                
            for payload in self.redirect_payloads:
                test_params = params.copy()
                test_params[param] = payload
                test_url = f"{url}?{urlencode(test_params)}"
                
                if test_url in self.tested_urls:
                    continue
                self.tested_urls.add(test_url)
                
                status, response, headers = await self.fetch(test_url)
                
                if status in [301, 302, 303, 307, 308]:
                    location = headers.get('Location', '')
                    if 'evil.com' in location or 'google.com' in location:
                        self.add_vulnerability(
                            severity="Medium",
                            vuln_type="Open Redirect",
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=f"Redirect to: {location}",
                            confidence="Confirmed",
                            remediation="Validate redirect URLs against a whitelist. Use relative URLs when possible."
                        )
                        print(f"[!] Open Redirect Found: {param} = {payload}")
                        
    async def test_security_headers(self):
        """Test for missing security headers"""
        print(f"[*] Testing Security Headers on: {self.target}")
        
        status, response, headers = await self.fetch(self.target)
        
        if not headers:
            return
            
        for header, description in self.security_headers.items():
            if header not in headers:
                self.add_vulnerability(
                    severity="Low",
                    vuln_type="Missing Security Header",
                    url=self.target,
                    parameter=header,
                    payload="N/A",
                    evidence=description,
                    confidence="Confirmed",
                    remediation=f"Add {header} header to all responses"
                )
                print(f"[!] Missing Header: {header}")
                
    async def test_admin_panel_detection(self):
        """Detect accessible admin panels"""
        print(f"[*] Testing for Admin Panels on: {self.target}")
        
        base_url = self.target.rstrip('/')
        
        tasks = []
        for path in self.admin_paths:
            test_url = base_url + path
            tasks.append(self._check_admin_path(test_url))
            
        await asyncio.gather(*tasks)
        
    async def _check_admin_path(self, url: str):
        """Check if admin path exists"""
        status, response, headers = await self.fetch(url)
        
        if status in [200, 301, 302, 401, 403]:
            self.add_vulnerability(
                severity="Info",
                vuln_type="Admin Panel Detection",
                url=url,
                parameter="N/A",
                payload="N/A",
                evidence=f"Status Code: {status}",
                confidence="Confirmed",
                remediation="Ensure admin panels are properly secured with strong authentication"
            )
            print(f"[!] Admin Panel Found: {url} (Status: {status})")
            
    async def test_broken_authentication(self, url: str):
        """Test for broken authentication and session management"""
        print(f"[*] Testing Authentication on: {url}")
        
        # Test common endpoints
        endpoints = ['/api/user/profile', '/dashboard', '/settings', '/account']
        
        for endpoint in endpoints:
            test_url = urljoin(self.target, endpoint)
            
            # Test without authentication
            status, response, headers = await self.fetch(test_url)
            
            if status == 200 and response:
                self.add_vulnerability(
                    severity="High",
                    vuln_type="Broken Authentication",
                    url=test_url,
                    parameter="N/A",
                    payload="No authentication",
                    evidence=f"Endpoint accessible without authentication. Status: {status}",
                    confidence="Confirmed",
                    remediation="Implement proper authentication checks on all protected endpoints"
                )
                print(f"[!] Broken Auth: {test_url} accessible without login")
                
    async def test_idor(self, url: str, params: dict):
        """Test for Insecure Direct Object Reference (IDOR)"""
        print(f"[*] Testing IDOR on: {url}")
        
        # Look for ID parameters
        id_params = ['id', 'user_id', 'userId', 'uid', 'order_id', 'orderId', 
                     'account', 'profile_id', 'doc_id', 'file_id']
        
        for param in params:
            if param.lower() not in id_params:
                continue
                
            original_value = params[param]
            
            # Try to parse as integer
            try:
                id_value = int(original_value)
                # Test with different IDs
                test_ids = [id_value + 1, id_value - 1, id_value + 10, 1, 999]
                
                # Get baseline
                baseline_url = f"{url}?{urlencode(params)}"
                baseline_status, baseline_response, _ = await self.fetch(baseline_url)
                
                for test_id in test_ids:
                    test_params = params.copy()
                    test_params[param] = str(test_id)
                    test_url = f"{url}?{urlencode(test_params)}"
                    
                    status, response, headers = await self.fetch(test_url)
                    
                    # If we get 200 with different content, possible IDOR
                    if status == 200 and response and response != baseline_response:
                        self.add_vulnerability(
                            severity="High",
                            vuln_type="Insecure Direct Object Reference (IDOR)",
                            url=url,
                            parameter=param,
                            payload=str(test_id),
                            evidence=f"Accessed different object with ID {test_id}",
                            confidence="Probable",
                            remediation="Implement proper authorization checks. Verify user has permission to access requested resource."
                        )
                        print(f"[!] Possible IDOR: {param} = {test_id}")
                        break
                        
            except ValueError:
                # Not a numeric ID
                continue
                
    async def crawl_and_test(self):
        """Main scanning workflow"""
        print(f"\n{'='*60}")
        print(f"Advanced Web Vulnerability Scanner")
        print(f"Target: {self.target}")
        print(f"{'='*60}\n")
        
        # Parse initial URL
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Convert params to simple dict
        simple_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        
        # If no params, use test params
        if not simple_params:
            simple_params = {'id': '1', 'search': 'test'}
        
        # Run all tests
        await asyncio.gather(
            self.test_security_headers(),
            self.test_admin_panel_detection(),
            self.test_broken_authentication(base_url),
            self.test_xss(base_url, simple_params),
            self.test_sqli(base_url, simple_params),
            self.test_open_redirect(base_url, simple_params),
            self.test_idor(base_url, simple_params),
        )
        
    def generate_report(self, output_format: str = 'json'):
        """Generate vulnerability report"""
        if output_format == 'json':
            return self._generate_json_report()
        elif output_format == 'html':
            return self._generate_html_report()
        else:
            return self._generate_text_report()
            
    def _generate_json_report(self) -> str:
        """Generate JSON format report"""
        report = {
            'target': self.target,
            'scan_date': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_breakdown': self._get_severity_breakdown(),
            'vulnerabilities': [asdict(v) for v in self.vulnerabilities]
        }
        return json.dumps(report, indent=2)
        
    def _get_severity_breakdown(self) -> dict:
        """Get count of vulnerabilities by severity"""
        breakdown = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for vuln in self.vulnerabilities:
            breakdown[vuln.severity] += 1
        return breakdown
        
    def _generate_html_report(self) -> str:
        """Generate HTML format report"""
        severity_breakdown = self._get_severity_breakdown()
        
        report_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scan Report - {html.escape(self.target)}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .stats {{ display: flex; justify-content: space-around; flex-wrap: wrap; }}
        .stat {{ text-align: center; padding: 15px; margin: 10px; background: white; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); min-width: 120px; }}
        .stat-number {{ font-size: 32px; font-weight: bold; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .info {{ color: #17a2b8; }}
        .vulnerability {{ border-left: 4px solid; padding: 15px; margin: 15px 0; background: #f8f9fa; border-radius: 5px; }}
        .vulnerability.Critical {{ border-color: #dc3545; }}
        .vulnerability.High {{ border-color: #fd7e14; }}
        .vulnerability.Medium {{ border-color: #ffc107; }}
        .vulnerability.Low {{ border-color: #28a745; }}
        .vulnerability.Info {{ border-color: #17a2b8; }}
        .vuln-header {{ font-size: 18px; font-weight: bold; margin-bottom: 10px; }}
        .vuln-detail {{ margin: 5px 0; }}
        .vuln-label {{ font-weight: bold; display: inline-block; width: 120px; }}
        code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px; font-family: monospace; }}
        .remediation {{ background: #d4edda; padding: 10px; margin-top: 10px; border-radius: 5px; border-left: 3px solid #28a745; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Web Vulnerability Scan Report</h1>
        
        <div class="summary">
            <p><strong>Target:</strong> {html.escape(self.target)}</p>
            <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Total Vulnerabilities:</strong> {len(self.vulnerabilities)}</p>
        </div>
        
        <h2>Severity Breakdown</h2>
        <div class="stats">
            <div class="stat">
                <div class="stat-number critical">{severity_breakdown['Critical']}</div>
                <div>Critical</div>
            </div>
            <div class="stat">
                <div class="stat-number high">{severity_breakdown['High']}</div>
                <div>High</div>
            </div>
            <div class="stat">
                <div class="stat-number medium">{severity_breakdown['Medium']}</div>
                <div>Medium</div>
            </div>
            <div class="stat">
                <div class="stat-number low">{severity_breakdown['Low']}</div>
                <div>Low</div>
            </div>
            <div class="stat">
                <div class="stat-number info">{severity_breakdown['Info']}</div>
                <div>Info</div>
            </div>
        </div>
        
        <h2>Vulnerability Details</h2>
"""
        
        for vuln in self.vulnerabilities:
            report_html += f"""
        <div class="vulnerability {vuln.severity}">
            <div class="vuln-header">{html.escape(vuln.type)}</div>
            <div class="vuln-detail"><span class="vuln-label">Severity:</span> {vuln.severity}</div>
            <div class="vuln-detail"><span class="vuln-label">Confidence:</span> {vuln.confidence}</div>
            <div class="vuln-detail"><span class="vuln-label">URL:</span> <code>{html.escape(vuln.url)}</code></div>
            <div class="vuln-detail"><span class="vuln-label">Parameter:</span> <code>{html.escape(vuln.parameter)}</code></div>
            <div class="vuln-detail"><span class="vuln-label">Payload:</span> <code>{html.escape(vuln.payload[:100])}</code></div>
            <div class="vuln-detail"><span class="vuln-label">Evidence:</span> {html.escape(vuln.evidence)}</div>
            <div class="remediation">
                <strong>💡 Remediation:</strong> {html.escape(vuln.remediation)}
            </div>
        </div>
"""
        
        report_html += """
    </div>
</body>
</html>
"""
        return report_html
        
    def _generate_text_report(self) -> str:
        """Generate plain text report"""
        report = f"""
{'='*60}
VULNERABILITY SCAN REPORT
{'='*60}

Target: {self.target}
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Vulnerabilities: {len(self.vulnerabilities)}

Severity Breakdown:
"""
        breakdown = self._get_severity_breakdown()
        for severity, count in breakdown.items():
            report += f"  {severity}: {count}\n"
            
        report += f"\n{'='*60}\nVULNERABILITY DETAILS\n{'='*60}\n\n"
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            report += f"""
[{i}] {vuln.type}
Severity: {vuln.severity}
Confidence: {vuln.confidence}
URL: {vuln.url}
Parameter: {vuln.parameter}
Payload: {vuln.payload[:100]}
Evidence: {vuln.evidence}
Remediation: {vuln.remediation}
{'-'*60}
"""
        
        return report

async def main():
    parser = argparse.ArgumentParser(
        description='Advanced Web Vulnerability Scanner',
        epilog='Example: python Hunter.py -u https://example.com -o report.html -f html'
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-o', '--output', default='report.json', help='Output file')
    parser.add_argument('-f', '--format', choices=['json', 'html', 'text'], 
                       default='json', help='Report format')
    parser.add_argument('-t', '--timeout', type=int, default=10, 
                       help='Request timeout in seconds')
    parser.add_argument('--threads', type=int, default=10, 
                       help='Number of concurrent requests')
    
    args = parser.parse_args()
    
    scanner = AdvancedWebScanner(
        target=args.url,
        timeout=args.timeout,
        threads=args.threads
    )
    
    try:
        await scanner.initialize()
        await scanner.crawl_and_test()
        
        # Generate and save report
        report = scanner.generate_report(args.format)
        
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report)
            
        print(f"\n{'='*60}")
        print(f"Scan Complete!")
        print(f"Found {len(scanner.vulnerabilities)} vulnerabilities")
        print(f"Report saved to: {args.output}")
        print(f"{'='*60}\n")
        
    finally:
        await scanner.close()

if __name__ == '__main__':
    asyncio.run(main())
