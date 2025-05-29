#!/usr/bin/env python3
"""
🔥 WASHBOT COMPLETE SYSTEM ANALYSIS & DEEP DIAGNOSTIC
Her dosya, her satır, her bağlantı, her paket analiz edilecek
Console hatalarının kökenini bulup tamamen temizleyeceğiz
"""

import os
import json
import re
import subprocess
import ast
import sys
from pathlib import Path
from typing import Dict, List, Any, Set
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class WashBotSystemAnalyzer:
    """
    WashBot için kapsamlı sistem analizi
    """
    
    def __init__(self):
        self.root_dir = Path(".")
        self.issues = []
        self.warnings = []
        self.critical_issues = []
        self.console_errors = []
        
        # Known console error patterns
        self.error_patterns = [
            "unhandledrejection",
            "cannot set properties of null",
            "TypeError",
            "ReferenceError",
            "undefined is not a function",
            "fetch failed",
            "Promise",
            "setInterval",
            "clearInterval"
        ]
        
    def scan_all_files(self):
        """Tüm dosyaları tara"""
        logger.info("🔍 Starting comprehensive file scan...")
        
        for file_path in self.root_dir.rglob("*"):
            if file_path.is_file() and not self._should_skip_file(file_path):
                self._analyze_file(file_path)
                
    def _should_skip_file(self, file_path: Path) -> bool:
        """Atlanacak dosyaları belirle"""
        skip_patterns = [
            "node_modules", ".git", "__pycache__", ".pyc", 
            ".log", "export_files", "attached_assets",
            ".lock", ".tar.gz", ".png", ".jpg", ".jpeg"
        ]
        
        return any(pattern in str(file_path) for pattern in skip_patterns)
    
    def _analyze_file(self, file_path: Path):
        """Tek dosyayı analiz et"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Check for console error patterns
            self._check_console_errors(file_path, content)
            
            # Analyze by file type
            if file_path.suffix == '.js':
                self._analyze_javascript(file_path, content)
            elif file_path.suffix == '.py':
                self._analyze_python(file_path, content)
            elif file_path.suffix in ['.html', '.htm']:
                self._analyze_html(file_path, content)
            elif file_path.suffix == '.json':
                self._analyze_json(file_path, content)
                
        except Exception as e:
            self.issues.append(f"File read error: {file_path} - {str(e)}")
    
    def _check_console_errors(self, file_path: Path, content: str):
        """Console hata kalıplarını kontrol et"""
        for pattern in self.error_patterns:
            if pattern.lower() in content.lower():
                self.console_errors.append({
                    'file': str(file_path),
                    'pattern': pattern,
                    'lines': self._find_lines_with_pattern(content, pattern)
                })
    
    def _find_lines_with_pattern(self, content: str, pattern: str) -> List[int]:
        """Kalıbı içeren satırları bul"""
        lines = []
        for i, line in enumerate(content.split('\n'), 1):
            if pattern.lower() in line.lower():
                lines.append(i)
        return lines
    
    def _analyze_javascript(self, file_path: Path, content: str):
        """JavaScript dosyalarını analiz et"""
        # Check for setInterval without clearInterval
        setinterval_count = content.count('setInterval')
        clearinterval_count = content.count('clearInterval')
        
        if setinterval_count > clearinterval_count:
            self.critical_issues.append(f"Memory leak: {file_path} has {setinterval_count} setInterval but only {clearinterval_count} clearInterval")
        
        # Check for Promise without catch
        promise_lines = self._find_lines_with_pattern(content, '.then(')
        for line_num in promise_lines:
            lines = content.split('\n')
            if line_num < len(lines):
                line = lines[line_num - 1]
                if '.catch(' not in line and 'await' not in line:
                    self.issues.append(f"Unhandled Promise at {file_path}:{line_num}")
        
        # Check for DOM manipulation without null checks
        dom_methods = ['getElementById', 'querySelector', 'getElementsByClassName']
        for method in dom_methods:
            if method in content:
                method_lines = self._find_lines_with_pattern(content, method)
                for line_num in method_lines:
                    lines = content.split('\n')
                    if line_num < len(lines):
                        line = lines[line_num - 1]
                        if 'if (' not in line and '?' not in line:
                            self.warnings.append(f"Possible null access at {file_path}:{line_num}")
    
    def _analyze_python(self, file_path: Path, content: str):
        """Python dosyalarını analiz et"""
        try:
            # Check for imports
            tree = ast.parse(content)
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module)
            
            # Check if all imports are available
            self._check_python_imports(file_path, imports)
            
        except SyntaxError as e:
            self.critical_issues.append(f"Python syntax error in {file_path}: {str(e)}")
        except Exception as e:
            self.warnings.append(f"Python analysis warning in {file_path}: {str(e)}")
    
    def _check_python_imports(self, file_path: Path, imports: List[str]):
        """Python import'larını kontrol et"""
        for imp in imports:
            try:
                __import__(imp)
            except ImportError:
                self.issues.append(f"Missing Python module: {imp} in {file_path}")
    
    def _analyze_html(self, file_path: Path, content: str):
        """HTML dosyalarını analiz et"""
        # Check for inline JavaScript with setInterval
        if 'setInterval' in content:
            setinterval_lines = self._find_lines_with_pattern(content, 'setInterval')
            for line_num in setinterval_lines:
                self.console_errors.append({
                    'file': str(file_path),
                    'pattern': 'setInterval in HTML',
                    'lines': [line_num]
                })
    
    def _analyze_json(self, file_path: Path, content: str):
        """JSON dosyalarını analiz et"""
        try:
            json.loads(content)
        except json.JSONDecodeError as e:
            self.critical_issues.append(f"Invalid JSON in {file_path}: {str(e)}")
    
    def check_package_dependencies(self):
        """Paket bağımlılıklarını kontrol et"""
        logger.info("🔍 Checking package dependencies...")
        
        # Check package.json
        package_json = self.root_dir / "package.json"
        if package_json.exists():
            try:
                with open(package_json, 'r') as f:
                    data = json.load(f)
                    
                dependencies = data.get('dependencies', {})
                dev_dependencies = data.get('devDependencies', {})
                
                logger.info(f"Found {len(dependencies)} dependencies and {len(dev_dependencies)} dev dependencies")
                
                # Check if node_modules exists
                if not (self.root_dir / "node_modules").exists():
                    self.critical_issues.append("node_modules directory missing - run 'npm install'")
                    
            except Exception as e:
                self.critical_issues.append(f"Error reading package.json: {str(e)}")
        
        # Check pyproject.toml
        pyproject = self.root_dir / "pyproject.toml"
        if pyproject.exists():
            logger.info("Found pyproject.toml - Python dependencies managed")
        
        # Check requirements.txt
        requirements = self.root_dir / "requirements.txt"
        if requirements.exists():
            logger.info("Found requirements.txt")
    
    def check_network_connections(self):
        """Ağ bağlantılarını kontrol et"""
        logger.info("🔍 Checking network connections...")
        
        # Common API endpoints to check
        endpoints = [
            "https://api.mainnet-beta.solana.com",
            "https://api.dexscreener.com",
            "https://quote-api.jup.ag",
            "https://api.raydium.io"
        ]
        
        for endpoint in endpoints:
            try:
                import requests
                response = requests.get(endpoint, timeout=5)
                if response.status_code != 200:
                    self.warnings.append(f"API endpoint {endpoint} returned status {response.status_code}")
                else:
                    logger.info(f"✅ {endpoint} is accessible")
            except Exception as e:
                self.issues.append(f"Cannot reach {endpoint}: {str(e)}")
    
    def check_environment_variables(self):
        """Çevre değişkenlerini kontrol et"""
        logger.info("🔍 Checking environment variables...")
        
        required_vars = [
            "DATABASE_URL",
            "SESSION_SECRET",
            "FLASK_SECRET_KEY"
        ]
        
        for var in required_vars:
            if not os.getenv(var):
                self.critical_issues.append(f"Missing environment variable: {var}")
            else:
                logger.info(f"✅ {var} is set")
    
    def find_setinterval_sources(self):
        """setInterval kaynaklarını detaylı olarak bul"""
        logger.info("🔍 Deep scan for setInterval sources...")
        
        setinterval_sources = []
        
        for file_path in self.root_dir.rglob("*.js"):
            if self._should_skip_file(file_path):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                lines = content.split('\n')
                for i, line in enumerate(lines, 1):
                    if 'setInterval' in line:
                        setinterval_sources.append({
                            'file': str(file_path),
                            'line': i,
                            'code': line.strip()
                        })
            except Exception as e:
                logger.warning(f"Could not read {file_path}: {e}")
        
        for file_path in self.root_dir.rglob("*.html"):
            if self._should_skip_file(file_path):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                lines = content.split('\n')
                for i, line in enumerate(lines, 1):
                    if 'setInterval' in line:
                        setinterval_sources.append({
                            'file': str(file_path),
                            'line': i,
                            'code': line.strip()
                        })
            except Exception as e:
                logger.warning(f"Could not read {file_path}: {e}")
        
        return setinterval_sources
    
    def generate_report(self) -> str:
        """Kapsamlı rapor oluştur"""
        report = []
        report.append("🔥 WASHBOT COMPLETE SYSTEM ANALYSIS REPORT")
        report.append("=" * 60)
        
        # Critical Issues
        if self.critical_issues:
            report.append("\n🚨 CRITICAL ISSUES (MUST FIX):")
            for issue in self.critical_issues:
                report.append(f"  ❌ {issue}")
        
        # Console Errors
        if self.console_errors:
            report.append("\n📺 CONSOLE ERROR SOURCES:")
            for error in self.console_errors:
                report.append(f"  🔴 {error['file']} - Pattern: {error['pattern']} at lines {error['lines']}")
        
        # setInterval Sources
        setinterval_sources = self.find_setinterval_sources()
        if setinterval_sources:
            report.append("\n⏰ setInterval SOURCES (POTENTIAL MEMORY LEAKS):")
            for source in setinterval_sources:
                report.append(f"  🔄 {source['file']}:{source['line']} - {source['code']}")
        
        # General Issues
        if self.issues:
            report.append("\n⚠️ ISSUES:")
            for issue in self.issues:
                report.append(f"  🔸 {issue}")
        
        # Warnings
        if self.warnings:
            report.append("\n💡 WARNINGS:")
            for warning in self.warnings:
                report.append(f"  🔹 {warning}")
        
        # Summary
        report.append("\n📊 SUMMARY:")
        report.append(f"  Critical Issues: {len(self.critical_issues)}")
        report.append(f"  Console Errors: {len(self.console_errors)}")
        report.append(f"  General Issues: {len(self.issues)}")
        report.append(f"  Warnings: {len(self.warnings)}")
        report.append(f"  setInterval Sources: {len(setinterval_sources)}")
        
        return "\n".join(report)
    
    def run_complete_analysis(self):
        """Tam analizi çalıştır"""
        logger.info("🚀 Starting WashBot Complete System Analysis...")
        
        self.scan_all_files()
        self.check_package_dependencies()
        self.check_environment_variables()
        
        try:
            self.check_network_connections()
        except ImportError:
            self.warnings.append("requests module not available for network checks")
        
        report = self.generate_report()
        
        # Save report
        with open("WASHBOT_SYSTEM_ANALYSIS_REPORT.txt", "w") as f:
            f.write(report)
        
        logger.info("✅ Analysis complete! Report saved to WASHBOT_SYSTEM_ANALYSIS_REPORT.txt")
        
        return report

def main():
    """Ana fonksiyon"""
    analyzer = WashBotSystemAnalyzer()
    report = analyzer.run_complete_analysis()
    print(report)
    
    return analyzer

if __name__ == "__main__":
    main()