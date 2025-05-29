"""
🛡️ WASHBOT COMPREHENSIVE SECURITY & CODE AUDIT 2025
Complete analysis of all code, security vulnerabilities, and system integrity
"""

import os
import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
import ast

class WashBotSecurityAudit:
    """
    Comprehensive security and code audit for WashBot
    Analyzing all vulnerabilities, code quality, and security issues
    """
    
    def __init__(self):
        self.audit_results = {
            'timestamp': datetime.now().isoformat(),
            'critical_issues': [],
            'security_vulnerabilities': [],
            'code_quality_issues': [],
            'configuration_issues': [],
            'database_issues': [],
            'frontend_issues': [],
            'api_security_issues': [],
            'recommendations': []
        }
        
        # File patterns to analyze
        self.file_patterns = {
            'python': ['*.py'],
            'javascript': ['*.js'],
            'html': ['*.html'],
            'config': ['*.json', '*.yaml', '*.yml', '*.env', '*.cfg']
        }
        
        # Security patterns to check
        self.security_patterns = {
            'sql_injection': [
                r'execute\s*\(\s*["\'].*%.*["\']',
                r'\.format\s*\(',
                r'f["\'].*\{.*\}.*["\']'
            ],
            'xss_vulnerabilities': [
                r'innerHTML\s*=',
                r'document\.write\s*\(',
                r'eval\s*\(',
                r'\$\{.*\}'
            ],
            'hardcoded_secrets': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'key\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][^"\']+["\']'
            ],
            'command_injection': [
                r'os\.system\s*\(',
                r'subprocess\.',
                r'shell=True'
            ]
        }
        
    def scan_directory(self, directory_path: str = '.') -> Dict[str, Any]:
        """Scan entire directory for security issues"""
        results = {
            'files_scanned': 0,
            'issues_found': 0,
            'file_issues': {}
        }
        
        for root, dirs, files in os.walk(directory_path):
            # Skip certain directories
            skip_dirs = {'.git', '__pycache__', 'node_modules', '.pytest_cache'}
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            
            for file in files:
                if self._should_scan_file(file):
                    file_path = os.path.join(root, file)
                    try:
                        file_issues = self._scan_file(file_path)
                        if file_issues:
                            results['file_issues'][file_path] = file_issues
                            results['issues_found'] += len(file_issues)
                        results['files_scanned'] += 1
                    except Exception as e:
                        self.audit_results['code_quality_issues'].append({
                            'file': file_path,
                            'issue': f'Failed to scan file: {str(e)}',
                            'severity': 'medium'
                        })
        
        return results
    
    def _should_scan_file(self, filename: str) -> bool:
        """Check if file should be scanned"""
        extensions = ['.py', '.js', '.html', '.json', '.yaml', '.yml']
        return any(filename.endswith(ext) for ext in extensions)
    
    def _scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan individual file for security issues"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Check for security patterns
            for category, patterns in self.security_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        line_number = content[:match.start()].count('\n') + 1
                        issues.append({
                            'category': category,
                            'pattern': pattern,
                            'line': line_number,
                            'match': match.group(),
                            'severity': self._get_severity(category)
                        })
            
            # File-specific checks
            if file_path.endswith('.py'):
                issues.extend(self._check_python_security(content, file_path))
            elif file_path.endswith('.js'):
                issues.extend(self._check_javascript_security(content, file_path))
            elif file_path.endswith('.html'):
                issues.extend(self._check_html_security(content, file_path))
                
        except Exception as e:
            issues.append({
                'category': 'file_error',
                'issue': f'Could not read file: {str(e)}',
                'severity': 'low'
            })
            
        return issues
    
    def _check_python_security(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Check Python-specific security issues"""
        issues = []
        
        # Check for unsafe imports
        unsafe_imports = ['pickle', 'cPickle', 'subprocess', 'os']
        for imp in unsafe_imports:
            if re.search(rf'import\s+{imp}', content) or re.search(rf'from\s+{imp}\s+import', content):
                issues.append({
                    'category': 'unsafe_import',
                    'issue': f'Potentially unsafe import: {imp}',
                    'severity': 'medium'
                })
        
        # Check for eval() usage
        if 'eval(' in content:
            issues.append({
                'category': 'code_injection',
                'issue': 'Use of eval() function - potential code injection',
                'severity': 'high'
            })
        
        # Check for exec() usage
        if 'exec(' in content:
            issues.append({
                'category': 'code_injection',
                'issue': 'Use of exec() function - potential code injection',
                'severity': 'high'
            })
        
        # Check for SQL queries without parameterization
        sql_patterns = [
            r'execute\s*\(\s*["\'].*%.*["\']',
            r'\.format\s*\(',
            r'f["\'].*SELECT.*\{.*\}.*["\']'
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                issues.append({
                    'category': 'sql_injection',
                    'issue': 'Potential SQL injection vulnerability',
                    'severity': 'critical'
                })
        
        return issues
    
    def _check_javascript_security(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Check JavaScript-specific security issues"""
        issues = []
        
        # Check for eval() usage
        if 'eval(' in content:
            issues.append({
                'category': 'code_injection',
                'issue': 'Use of eval() function - potential XSS/code injection',
                'severity': 'high'
            })
        
        # Check for innerHTML without sanitization
        if re.search(r'innerHTML\s*=\s*[^;]*[+]', content):
            issues.append({
                'category': 'xss_vulnerability',
                'issue': 'Potential XSS via innerHTML without sanitization',
                'severity': 'high'
            })
        
        # Check for document.write
        if 'document.write(' in content:
            issues.append({
                'category': 'xss_vulnerability',
                'issue': 'Use of document.write() - potential XSS',
                'severity': 'medium'
            })
        
        return issues
    
    def _check_html_security(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Check HTML-specific security issues"""
        issues = []
        
        # Check for inline scripts
        if re.search(r'<script[^>]*>', content, re.IGNORECASE):
            issues.append({
                'category': 'inline_script',
                'issue': 'Inline JavaScript found - potential CSP issues',
                'severity': 'medium'
            })
        
        # Check for external script loading without integrity
        script_matches = re.finditer(r'<script[^>]*src\s*=\s*["\']https?://[^"\']*["\'][^>]*>', content, re.IGNORECASE)
        for match in script_matches:
            if 'integrity=' not in match.group():
                issues.append({
                    'category': 'resource_integrity',
                    'issue': 'External script without integrity check',
                    'severity': 'medium'
                })
        
        return issues
    
    def _get_severity(self, category: str) -> str:
        """Get severity level for security category"""
        severity_map = {
            'sql_injection': 'critical',
            'command_injection': 'critical',
            'code_injection': 'high',
            'xss_vulnerability': 'high',
            'hardcoded_secrets': 'high',
            'unsafe_import': 'medium',
            'inline_script': 'medium',
            'resource_integrity': 'medium'
        }
        return severity_map.get(category, 'low')
    
    def audit_database_configuration(self) -> List[Dict[str, Any]]:
        """Audit database configuration for security issues"""
        issues = []
        
        # Check for database configuration files
        config_files = ['app.py', 'config.py', 'database.py']
        
        for file_path in config_files:
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                    
                    # Check for hardcoded database credentials
                    if re.search(r'DATABASE_URL\s*=\s*["\'][^"\']*://[^"\']*:[^"\']*@', content):
                        issues.append({
                            'file': file_path,
                            'issue': 'Hardcoded database credentials found',
                            'severity': 'critical'
                        })
                    
                    # Check for SQL injection vulnerabilities
                    if re.search(r'execute\s*\(\s*["\'].*%.*["\']', content):
                        issues.append({
                            'file': file_path,
                            'issue': 'Potential SQL injection vulnerability',
                            'severity': 'critical'
                        })
                    
                except Exception as e:
                    issues.append({
                        'file': file_path,
                        'issue': f'Could not analyze file: {str(e)}',
                        'severity': 'medium'
                    })
        
        return issues
    
    def audit_api_security(self) -> List[Dict[str, Any]]:
        """Audit API endpoints for security issues"""
        issues = []
        
        # Check Flask routes for security issues
        python_files = [f for f in os.listdir('.') if f.endswith('.py')]
        
        for file_path in python_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Check for missing authentication
                routes = re.finditer(r'@app\.route\s*\([^)]*\)', content)
                for route_match in routes:
                    route_line = content[:route_match.end()].count('\n') + 1
                    route_code = content[route_match.end():route_match.end()+500]
                    
                    if '@login_required' not in route_code and '@require_login' not in route_code:
                        issues.append({
                            'file': file_path,
                            'line': route_line,
                            'issue': 'API endpoint without authentication check',
                            'severity': 'high'
                        })
                
                # Check for CSRF protection
                if 'csrf' not in content.lower() and '@app.route' in content:
                    issues.append({
                        'file': file_path,
                        'issue': 'Missing CSRF protection in Flask routes',
                        'severity': 'medium'
                    })
                
            except Exception as e:
                issues.append({
                    'file': file_path,
                    'issue': f'Could not analyze API security: {str(e)}',
                    'severity': 'low'
                })
        
        return issues
    
    def audit_frontend_security(self) -> List[Dict[str, Any]]:
        """Audit frontend security issues"""
        issues = []
        
        # Check HTML templates
        template_dirs = ['templates', 'static']
        
        for template_dir in template_dirs:
            if os.path.exists(template_dir):
                for root, dirs, files in os.walk(template_dir):
                    for file in files:
                        if file.endswith(('.html', '.js')):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r') as f:
                                    content = f.read()
                                
                                # Check for XSS vulnerabilities
                                if '{{' in content and '|safe' in content:
                                    issues.append({
                                        'file': file_path,
                                        'issue': 'Unsafe template rendering detected',
                                        'severity': 'high'
                                    })
                                
                                # Check for missing CSP headers
                                if file.endswith('.html') and 'Content-Security-Policy' not in content:
                                    issues.append({
                                        'file': file_path,
                                        'issue': 'Missing Content Security Policy',
                                        'severity': 'medium'
                                    })
                                
                            except Exception as e:
                                issues.append({
                                    'file': file_path,
                                    'issue': f'Could not analyze frontend file: {str(e)}',
                                    'severity': 'low'
                                })
        
        return issues
    
    def check_dependencies(self) -> List[Dict[str, Any]]:
        """Check for vulnerable dependencies"""
        issues = []
        
        # Check Python dependencies
        if os.path.exists('requirements.txt'):
            try:
                with open('requirements.txt', 'r') as f:
                    requirements = f.read()
                
                # Known vulnerable packages (example)
                vulnerable_packages = ['flask<2.0', 'requests<2.20', 'jinja2<2.10']
                
                for package in vulnerable_packages:
                    if package.split('<')[0] in requirements:
                        issues.append({
                            'file': 'requirements.txt',
                            'issue': f'Potentially vulnerable package: {package}',
                            'severity': 'medium'
                        })
                        
            except Exception as e:
                issues.append({
                    'file': 'requirements.txt',
                    'issue': f'Could not check dependencies: {str(e)}',
                    'severity': 'low'
                })
        
        return issues
    
    def run_comprehensive_audit(self) -> Dict[str, Any]:
        """Run complete security audit"""
        print("🔍 Starting comprehensive security audit...")
        
        # Scan all files
        scan_results = self.scan_directory('.')
        print(f"📁 Scanned {scan_results['files_scanned']} files")
        
        # Database security audit
        db_issues = self.audit_database_configuration()
        self.audit_results['database_issues'] = db_issues
        
        # API security audit
        api_issues = self.audit_api_security()
        self.audit_results['api_security_issues'] = api_issues
        
        # Frontend security audit
        frontend_issues = self.audit_frontend_security()
        self.audit_results['frontend_issues'] = frontend_issues
        
        # Dependency check
        dep_issues = self.check_dependencies()
        self.audit_results['configuration_issues'] = dep_issues
        
        # Categorize issues by severity
        for file_path, file_issues in scan_results['file_issues'].items():
            for issue in file_issues:
                issue['file'] = file_path
                
                if issue['severity'] == 'critical':
                    self.audit_results['critical_issues'].append(issue)
                elif issue['severity'] == 'high':
                    self.audit_results['security_vulnerabilities'].append(issue)
                else:
                    self.audit_results['code_quality_issues'].append(issue)
        
        # Add specific recommendations
        self._generate_recommendations()
        
        return self.audit_results
    
    def _generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = [
            "Implement Content Security Policy (CSP) headers",
            "Add CSRF protection to all forms",
            "Use parameterized queries for all database operations",
            "Implement rate limiting on API endpoints",
            "Add input validation and sanitization",
            "Use HTTPS for all communications",
            "Implement proper session management",
            "Add security headers (X-Frame-Options, X-Content-Type-Options)",
            "Regular security dependency updates",
            "Implement proper error handling without information disclosure"
        ]
        
        self.audit_results['recommendations'] = recommendations
    
    def generate_report(self) -> str:
        """Generate comprehensive security report"""
        report = f"""
🛡️ WASHBOT COMPREHENSIVE SECURITY AUDIT REPORT
Generated: {self.audit_results['timestamp']}

📊 SUMMARY:
- Critical Issues: {len(self.audit_results['critical_issues'])}
- Security Vulnerabilities: {len(self.audit_results['security_vulnerabilities'])}
- Code Quality Issues: {len(self.audit_results['code_quality_issues'])}
- Database Issues: {len(self.audit_results['database_issues'])}
- API Security Issues: {len(self.audit_results['api_security_issues'])}
- Frontend Issues: {len(self.audit_results['frontend_issues'])}

🚨 CRITICAL ISSUES:
"""
        
        for issue in self.audit_results['critical_issues']:
            report += f"- {issue.get('file', 'Unknown')}: {issue.get('issue', 'Unknown issue')}\n"
        
        report += f"""
⚠️ SECURITY VULNERABILITIES:
"""
        
        for issue in self.audit_results['security_vulnerabilities']:
            report += f"- {issue.get('file', 'Unknown')}: {issue.get('issue', 'Unknown issue')}\n"
        
        report += f"""
💡 RECOMMENDATIONS:
"""
        
        for rec in self.audit_results['recommendations']:
            report += f"- {rec}\n"
        
        return report

def main():
    """Run the comprehensive security audit"""
    auditor = WashBotSecurityAudit()
    results = auditor.run_comprehensive_audit()
    report = auditor.generate_report()
    
    # Save results
    with open('security_audit_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    with open('security_audit_report.txt', 'w') as f:
        f.write(report)
    
    print(report)
    return results

if __name__ == "__main__":
    main()