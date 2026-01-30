# Phantom  |   Advanced Web Vulnerability Scanner

# Web Scanner
python Hunter.py -u example.com  -o report.html -f html
python Hunter.py -u "https://example.com/page.php?id=1&name=test" -f html -o vuln_report.html
python Hunter.py -u https://example.com /page?id=1 -o app_scan.html -f html

# Security Headers Analyzer
python Angel.py -u example.com -o headers.html -f html
python Angel.py -u example.com -o headers.html -f html
python Angel.py -d bugbounty.com -t 100 -o subdomains.json -f json

# Subdomain Enum
python Mage.py -d example.com -o subs.csv

# Mini WAF Engine
python Moon.py --test --report test_results.json --format json

# Log Attack Analyzer
python Beast.py -l /var/log/apache2/access.log -o attacks.html -f html
