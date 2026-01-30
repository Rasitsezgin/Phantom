#!/usr/bin/env python3
"""
Security Headers Analyzer
Comprehensive security headers analysis tool
Author: Security Research Team
License: MIT
"""

import requests
import argparse
import json
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import re

@dataclass
class HeaderCheck:
    """Security header check result"""
    header: str
    present: bool
    value: str
    score: int
    max_score: int
    severity: str
    recommendations: List[str]
    details: str

class SecurityHeadersAnalyzer:
    """Analyze HTTP security headers and provide recommendations"""
    
    def __init__(self, url: str):
        self.url = url if url.startswith('http') else f'https://{url}'
        self.headers = {}
        self.checks: List[HeaderCheck] = []
        self.total_score = 0
        self.max_possible_score = 0
        
    def fetch_headers(self) -> bool:
        """Fetch HTTP headers from target"""
        try:
            print(f"[*] Fetching headers from: {self.url}")
            response = requests.get(self.url, timeout=10, allow_redirects=True)
            self.headers = dict(response.headers)
            print(f"[+] Headers received (Status: {response.status_code})")
            return True
        except Exception as e:
            print(f"[-] Error fetching headers: {e}")
            return False
            
    def check_csp(self):
        """Check Content-Security-Policy header"""
        header_name = 'Content-Security-Policy'
        value = self.headers.get(header_name, '')
        
        if not value:
            self.checks.append(HeaderCheck(
                header=header_name,
                present=False,
                value='',
                score=0,
                max_score=25,
                severity='High',
                recommendations=[
                    "Implement Content-Security-Policy to prevent XSS attacks",
                    "Start with CSP in report-only mode to test",
                    "Example: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
                    "Gradually tighten policy by removing 'unsafe-inline' and 'unsafe-eval'",
                ],
                details="CSP helps prevent XSS, clickjacking, and other code injection attacks"
            ))
            return
            
        # Analyze CSP quality
        score = 0
        recommendations = []
        issues = []
        
        # Check for dangerous directives
        if "'unsafe-inline'" in value:
            issues.append("Uses 'unsafe-inline' which weakens XSS protection")
            recommendations.append("Remove 'unsafe-inline' and use nonces or hashes instead")
        else:
            score += 5
            
        if "'unsafe-eval'" in value:
            issues.append("Uses 'unsafe-eval' which allows dangerous eval() calls")
            recommendations.append("Remove 'unsafe-eval'")
        else:
            score += 5
            
        # Check for important directives
        directives = ['default-src', 'script-src', 'style-src', 'img-src', 'font-src']
        for directive in directives:
            if directive in value:
                score += 2
            else:
                recommendations.append(f"Add '{directive}' directive")
                
        # Check for report-uri or report-to
        if 'report-uri' in value or 'report-to' in value:
            score += 3
        else:
            recommendations.append("Add 'report-uri' or 'report-to' for violation reporting")
            
        if not issues:
            issues.append("CSP is properly configured")
            
        self.checks.append(HeaderCheck(
            header=header_name,
            present=True,
            value=value[:100] + '...' if len(value) > 100 else value,
            score=score,
            max_score=25,
            severity='High' if score < 15 else 'Medium',
            recommendations=recommendations if recommendations else ["CSP is well configured"],
            details="; ".join(issues)
        ))
        
    def check_hsts(self):
        """Check Strict-Transport-Security header"""
        header_name = 'Strict-Transport-Security'
        value = self.headers.get(header_name, '')
        
        if not value:
            self.checks.append(HeaderCheck(
                header=header_name,
                present=False,
                value='',
                score=0,
                max_score=15,
                severity='High',
                recommendations=[
                    "Implement HSTS to enforce HTTPS connections",
                    "Example: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    "Start with shorter max-age (e.g., 300) for testing",
                    "Consider HSTS preload list submission"
                ],
                details="HSTS prevents protocol downgrade attacks and cookie hijacking"
            ))
            return
            
        score = 0
        recommendations = []
        
        # Extract max-age
        max_age_match = re.search(r'max-age=(\d+)', value)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age >= 31536000:  # 1 year
                score += 10
            elif max_age >= 15768000:  # 6 months
                score += 7
                recommendations.append("Increase max-age to at least 31536000 (1 year)")
            else:
                score += 4
                recommendations.append("Increase max-age to at least 31536000 (1 year)")
        else:
            recommendations.append("Add max-age directive")
            
        # Check for includeSubDomains
        if 'includeSubDomains' in value:
            score += 3
        else:
            recommendations.append("Add 'includeSubDomains' directive")
            
        # Check for preload
        if 'preload' in value:
            score += 2
        else:
            recommendations.append("Consider adding 'preload' directive for browser preload list")
            
        self.checks.append(HeaderCheck(
            header=header_name,
            present=True,
            value=value,
            score=score,
            max_score=15,
            severity='Low' if score >= 10 else 'Medium',
            recommendations=recommendations if recommendations else ["HSTS is well configured"],
            details=f"HSTS configured with max-age={max_age_match.group(1) if max_age_match else 'N/A'}"
        ))
        
    def check_x_frame_options(self):
        """Check X-Frame-Options header"""
        header_name = 'X-Frame-Options'
        value = self.headers.get(header_name, '')
        
        if not value:
            # Check if CSP has frame-ancestors
            csp = self.headers.get('Content-Security-Policy', '')
            if 'frame-ancestors' in csp:
                self.checks.append(HeaderCheck(
                    header=header_name,
                    present=False,
                    value='',
                    score=10,
                    max_score=10,
                    severity='Info',
                    recommendations=["Using CSP frame-ancestors instead (recommended modern approach)"],
                    details="Protected by CSP frame-ancestors directive"
                ))
                return
                
            self.checks.append(HeaderCheck(
                header=header_name,
                present=False,
                value='',
                score=0,
                max_score=10,
                severity='Medium',
                recommendations=[
                    "Implement X-Frame-Options to prevent clickjacking",
                    "Recommended value: X-Frame-Options: DENY",
                    "Alternative: X-Frame-Options: SAMEORIGIN",
                    "Or use CSP frame-ancestors directive (modern approach)"
                ],
                details="Missing clickjacking protection"
            ))
            return
            
        score = 10 if value.upper() in ['DENY', 'SAMEORIGIN'] else 5
        
        self.checks.append(HeaderCheck(
            header=header_name,
            present=True,
            value=value,
            score=score,
            max_score=10,
            severity='Low',
            recommendations=[] if score == 10 else ["Use DENY or SAMEORIGIN"],
            details=f"Clickjacking protection: {value}"
        ))
        
    def check_x_content_type_options(self):
        """Check X-Content-Type-Options header"""
        header_name = 'X-Content-Type-Options'
        value = self.headers.get(header_name, '')
        
        if not value:
            self.checks.append(HeaderCheck(
                header=header_name,
                present=False,
                value='',
                score=0,
                max_score=10,
                severity='Low',
                recommendations=[
                    "Add X-Content-Type-Options: nosniff",
                    "Prevents MIME-sniffing attacks"
                ],
                details="Missing MIME-sniffing protection"
            ))
            return
            
        score = 10 if value.lower() == 'nosniff' else 5
        
        self.checks.append(HeaderCheck(
            header=header_name,
            present=True,
            value=value,
            score=score,
            max_score=10,
            severity='Low',
            recommendations=[] if score == 10 else ["Value should be 'nosniff'"],
            details="MIME-sniffing protection enabled"
        ))
        
    def check_referrer_policy(self):
        """Check Referrer-Policy header"""
        header_name = 'Referrer-Policy'
        value = self.headers.get(header_name, '')
        
        if not value:
            self.checks.append(HeaderCheck(
                header=header_name,
                present=False,
                value='',
                score=0,
                max_score=10,
                severity='Low',
                recommendations=[
                    "Add Referrer-Policy header to control referrer information",
                    "Recommended: Referrer-Policy: strict-origin-when-cross-origin",
                    "Or: Referrer-Policy: no-referrer for maximum privacy"
                ],
                details="Referrer information may leak to third parties"
            ))
            return
            
        # Preferred values
        good_policies = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin']
        score = 10 if value in good_policies else 5
        
        self.checks.append(HeaderCheck(
            header=header_name,
            present=True,
            value=value,
            score=score,
            max_score=10,
            severity='Low',
            recommendations=[] if score == 10 else ["Consider using 'strict-origin-when-cross-origin'"],
            details=f"Referrer policy: {value}"
        ))
        
    def check_permissions_policy(self):
        """Check Permissions-Policy header"""
        header_name = 'Permissions-Policy'
        value = self.headers.get(header_name, self.headers.get('Feature-Policy', ''))
        
        if not value:
            self.checks.append(HeaderCheck(
                header=header_name,
                present=False,
                value='',
                score=0,
                max_score=10,
                severity='Low',
                recommendations=[
                    "Add Permissions-Policy to control browser features",
                    "Example: Permissions-Policy: geolocation=(), microphone=(), camera=()",
                    "Restrict features your site doesn't need"
                ],
                details="Browser features not restricted"
            ))
            return
            
        # Count restricted features
        restricted_features = len(re.findall(r'=\(\)', value))
        score = min(10, restricted_features * 2)
        
        self.checks.append(HeaderCheck(
            header=header_name,
            present=True,
            value=value[:100] + '...' if len(value) > 100 else value,
            score=score,
            max_score=10,
            severity='Low',
            recommendations=["Good feature policy configuration"] if score >= 8 else ["Restrict more unused features"],
            details=f"Restricts {restricted_features} browser features"
        ))
        
    def check_x_xss_protection(self):
        """Check X-XSS-Protection header"""
        header_name = 'X-XSS-Protection'
        value = self.headers.get(header_name, '')
        
        # Note: This header is deprecated, CSP is preferred
        if not value:
            csp = self.headers.get('Content-Security-Policy', '')
            if csp:
                self.checks.append(HeaderCheck(
                    header=header_name,
                    present=False,
                    value='',
                    score=5,
                    max_score=5,
                    severity='Info',
                    recommendations=["Using CSP instead (recommended - X-XSS-Protection is deprecated)"],
                    details="CSP provides better XSS protection than X-XSS-Protection"
                ))
                return
                
            self.checks.append(HeaderCheck(
                header=header_name,
                present=False,
                value='',
                score=0,
                max_score=5,
                severity='Low',
                recommendations=[
                    "Add X-XSS-Protection: 1; mode=block (for legacy browsers)",
                    "Better: Implement Content-Security-Policy"
                ],
                details="No XSS protection header (legacy)"
            ))
            return
            
        score = 5 if '1' in value else 2
        
        self.checks.append(HeaderCheck(
            header=header_name,
            present=True,
            value=value,
            score=score,
            max_score=5,
            severity='Info',
            recommendations=["Header is deprecated; focus on CSP instead"],
            details="Legacy XSS protection enabled (deprecated)"
        ))
        
    def check_additional_headers(self):
        """Check for additional security-related headers"""
        # Server header disclosure
        server = self.headers.get('Server', '')
        if server:
            detailed_server = any(ver in server.lower() for ver in ['/', 'apache', 'nginx', 'iis', 'version'])
            if detailed_server:
                self.checks.append(HeaderCheck(
                    header='Server',
                    present=True,
                    value=server,
                    score=0,
                    max_score=5,
                    severity='Info',
                    recommendations=["Remove version information from Server header"],
                    details="Server version disclosure may aid attackers"
                ))
        
        # X-Powered-By disclosure
        powered_by = self.headers.get('X-Powered-By', '')
        if powered_by:
            self.checks.append(HeaderCheck(
                header='X-Powered-By',
                present=True,
                value=powered_by,
                score=0,
                max_score=5,
                severity='Info',
                recommendations=["Remove X-Powered-By header to avoid technology disclosure"],
                details="Technology stack disclosure"
            ))
            
    def analyze(self):
        """Run all header checks"""
        print(f"\n{'='*60}")
        print(f"Security Headers Analysis")
        print(f"Target: {self.url}")
        print(f"{'='*60}\n")
        
        if not self.fetch_headers():
            return False
            
        # Run all checks
        self.check_csp()
        self.check_hsts()
        self.check_x_frame_options()
        self.check_x_content_type_options()
        self.check_referrer_policy()
        self.check_permissions_policy()
        self.check_x_xss_protection()
        self.check_additional_headers()
        
        # Calculate scores
        self.total_score = sum(check.score for check in self.checks)
        self.max_possible_score = sum(check.max_score for check in self.checks)
        
        return True
        
    def get_grade(self) -> str:
        """Calculate letter grade based on score"""
        percentage = (self.total_score / self.max_possible_score * 100) if self.max_possible_score > 0 else 0
        
        if percentage >= 90:
            return 'A'
        elif percentage >= 80:
            return 'B'
        elif percentage >= 70:
            return 'C'
        elif percentage >= 60:
            return 'D'
        else:
            return 'F'
            
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
        report = {
            'url': self.url,
            'scan_date': datetime.now().isoformat(),
            'score': self.total_score,
            'max_score': self.max_possible_score,
            'percentage': round(self.total_score / self.max_possible_score * 100, 2) if self.max_possible_score > 0 else 0,
            'grade': self.get_grade(),
            'headers': [asdict(check) for check in self.checks]
        }
        return json.dumps(report, indent=2)
        
    def _generate_html(self) -> str:
        """Generate HTML report"""
        from html import escape
        
        percentage = (self.total_score / self.max_possible_score * 100) if self.max_possible_score > 0 else 0
        grade = self.get_grade()
        grade_color = {'A': '#28a745', 'B': '#20c997', 'C': '#ffc107', 'D': '#fd7e14', 'F': '#dc3545'}.get(grade, '#6c757d')
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Headers Report - {escape(self.url)}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; border-radius: 15px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 32px; }}
        .header .url {{ margin-top: 10px; opacity: 0.9; font-size: 16px; }}
        .score-section {{ padding: 30px; text-align: center; background: #f8f9fa; }}
        .score-circle {{ width: 200px; height: 200px; margin: 0 auto; border-radius: 50%; background: {grade_color}; display: flex; align-items: center; justify-content: center; flex-direction: column; color: white; box-shadow: 0 5px 20px rgba(0,0,0,0.2); }}
        .score-circle .grade {{ font-size: 80px; font-weight: bold; line-height: 1; }}
        .score-circle .percentage {{ font-size: 20px; margin-top: 5px; }}
        .score-details {{ margin-top: 20px; font-size: 18px; color: #666; }}
        .checks {{ padding: 30px; }}
        .check {{ margin: 20px 0; padding: 20px; border-left: 4px solid; border-radius: 5px; background: #f8f9fa; }}
        .check.present {{ border-color: #28a745; }}
        .check.missing {{ border-color: #dc3545; }}
        .check-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
        .check-title {{ font-size: 20px; font-weight: bold; }}
        .check-score {{ font-size: 18px; padding: 5px 15px; background: white; border-radius: 20px; }}
        .severity {{ display: inline-block; padding: 3px 10px; border-radius: 3px; font-size: 12px; font-weight: bold; color: white; }}
        .severity.High {{ background: #dc3545; }}
        .severity.Medium {{ background: #fd7e14; }}
        .severity.Low {{ background: #ffc107; color: #333; }}
        .severity.Info {{ background: #17a2b8; }}
        .value {{ background: white; padding: 10px; border-radius: 5px; font-family: monospace; margin: 10px 0; word-break: break-all; }}
        .recommendations {{ margin-top: 15px; }}
        .recommendations ul {{ margin: 10px 0; padding-left: 20px; }}
        .recommendations li {{ margin: 5px 0; }}
        .details {{ color: #666; font-style: italic; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Headers Analysis</h1>
            <div class="url">{escape(self.url)}</div>
        </div>
        
        <div class="score-section">
            <div class="score-circle">
                <div class="grade">{grade}</div>
                <div class="percentage">{percentage:.1f}%</div>
            </div>
            <div class="score-details">
                Score: {self.total_score} / {self.max_possible_score} points
            </div>
        </div>
        
        <div class="checks">
            <h2>Header Analysis</h2>
"""
        
        for check in self.checks:
            status_class = 'present' if check.present else 'missing'
            status_icon = '✓' if check.present else '✗'
            
            html += f"""
            <div class="check {status_class}">
                <div class="check-header">
                    <span class="check-title">{status_icon} {escape(check.header)}</span>
                    <span class="check-score">{check.score}/{check.max_score}</span>
                </div>
                <div><span class="severity {check.severity}">{check.severity}</span></div>
"""
            
            if check.value:
                html += f'<div class="value">{escape(check.value)}</div>'
                
            html += f'<div class="details">{escape(check.details)}</div>'
            
            if check.recommendations:
                html += '<div class="recommendations"><strong>Recommendations:</strong><ul>'
                for rec in check.recommendations:
                    html += f'<li>{escape(rec)}</li>'
                html += '</ul></div>'
                
            html += '</div>'
        
        html += """
        </div>
    </div>
</body>
</html>
"""
        return html
        
    def _generate_text(self) -> str:
        """Generate text report"""
        percentage = (self.total_score / self.max_possible_score * 100) if self.max_possible_score > 0 else 0
        
        report = f"""
{'='*60}
SECURITY HEADERS ANALYSIS REPORT
{'='*60}

Target: {self.url}
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

OVERALL SCORE
Score: {self.total_score}/{self.max_possible_score} ({percentage:.1f}%)
Grade: {self.get_grade()}

{'='*60}
HEADER DETAILS
{'='*60}

"""
        
        for check in self.checks:
            status = '✓ PRESENT' if check.present else '✗ MISSING'
            report += f"""
{check.header}: {status}
Score: {check.score}/{check.max_score}
Severity: {check.severity}
"""
            
            if check.value:
                report += f"Value: {check.value}\n"
                
            report += f"Details: {check.details}\n"
            
            if check.recommendations:
                report += "Recommendations:\n"
                for rec in check.recommendations:
                    report += f"  - {rec}\n"
                    
            report += f"{'-'*60}\n"
        
        return report

def main():
    parser = argparse.ArgumentParser(
        description='Security Headers Analyzer',
        epilog='Example: python headers_analyzer.py -u example.com -o report.html -f html'
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-o', '--output', default='headers_report.json', help='Output file')
    parser.add_argument('-f', '--format', choices=['json', 'html', 'text'],
                       default='json', help='Output format')
    
    args = parser.parse_args()
    
    analyzer = SecurityHeadersAnalyzer(args.url)
    
    if analyzer.analyze():
        report = analyzer.generate_report(args.format)
        
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report)
            
        # Print summary
        percentage = (analyzer.total_score / analyzer.max_possible_score * 100) if analyzer.max_possible_score > 0 else 0
        print(f"\n{'='*60}")
        print(f"Analysis Complete!")
        print(f"Score: {analyzer.total_score}/{analyzer.max_possible_score} ({percentage:.1f}%)")
        print(f"Grade: {analyzer.get_grade()}")
        print(f"Report saved to: {args.output}")
        print(f"{'='*60}\n")

if __name__ == '__main__':
    main()
