"""
🔥 WASHBOT FINAL DEPLOY AUDIT
Deploy öncesi kapsamlı sistem kontrolü
Her API, entegrasyon, veri akışı ve protokol kontrol edilecek
"""

import os
import sys
import json
import logging
import asyncio
import aiohttp
from pathlib import Path
from typing import Dict, List, Any, Optional
import subprocess
import importlib.util

# Logging ayarları
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class FinalDeployAudit:
    """
    Deploy öncesi kapsamlı sistem audit'i
    """
    
    def __init__(self):
        self.audit_results = {
            'critical_errors': [],
            'warnings': [],
            'passed_checks': [],
            'api_status': {},
            'database_status': {},
            'integration_status': {},
            'security_status': {}
        }
        
    def audit_python_imports(self) -> Dict[str, Any]:
        """Python import'larını kontrol et"""
        logger.info("🔍 Python import'ları kontrol ediliyor...")
        
        required_imports = [
            'flask', 'sqlalchemy', 'requests', 'aiohttp', 
            'solana', 'cryptography', 'jwt', 'qrcode',
            'psycopg2', 'werkzeug', 'gunicorn'
        ]
        
        import_status = {}
        
        for module in required_imports:
            try:
                __import__(module)
                import_status[module] = "✅ OK"
                self.audit_results['passed_checks'].append(f"Import {module} başarılı")
            except ImportError as e:
                import_status[module] = f"❌ FAILED: {e}"
                self.audit_results['critical_errors'].append(f"Import hatası: {module} - {e}")
                
        return import_status
    
    def audit_environment_variables(self) -> Dict[str, Any]:
        """Çevre değişkenlerini kontrol et"""
        logger.info("🔍 Çevre değişkenleri kontrol ediliyor...")
        
        required_env_vars = [
            'DATABASE_URL', 'PGHOST', 'PGPORT', 'PGUSER', 
            'PGPASSWORD', 'PGDATABASE'
        ]
        
        env_status = {}
        
        for var in required_env_vars:
            value = os.environ.get(var)
            if value:
                env_status[var] = "✅ SET"
                self.audit_results['passed_checks'].append(f"Environment variable {var} mevcut")
            else:
                env_status[var] = "❌ MISSING"
                self.audit_results['critical_errors'].append(f"Environment variable eksik: {var}")
                
        return env_status
    
    def audit_file_structure(self) -> Dict[str, Any]:
        """Dosya yapısını kontrol et"""
        logger.info("🔍 Dosya yapısı kontrol ediliyor...")
        
        critical_files = [
            'app.py', 'main.py', 'models.py', 'config.py',
            'wallet_manager.py', 'solana_utils.py', 'strategies.py',
            'templates/layout.html', 'templates/index.html', 
            'templates/token_creator.html', 'static/js/main.js'
        ]
        
        file_status = {}
        
        for file_path in critical_files:
            if os.path.exists(file_path):
                file_status[file_path] = "✅ EXISTS"
                self.audit_results['passed_checks'].append(f"Kritik dosya mevcut: {file_path}")
            else:
                file_status[file_path] = "❌ MISSING"
                self.audit_results['critical_errors'].append(f"Kritik dosya eksik: {file_path}")
                
        return file_status
    
    async def audit_database_connectivity(self) -> Dict[str, Any]:
        """Veritabanı bağlantısını test et"""
        logger.info("🔍 Veritabanı bağlantısı test ediliyor...")
        
        try:
            import psycopg2
            
            # Database connection test
            conn_params = {
                'host': os.environ.get('PGHOST'),
                'port': os.environ.get('PGPORT'),
                'user': os.environ.get('PGUSER'),
                'password': os.environ.get('PGPASSWORD'),
                'database': os.environ.get('PGDATABASE')
            }
            
            conn = psycopg2.connect(**conn_params)
            cursor = conn.cursor()
            
            # Test basic queries
            cursor.execute("SELECT version();")
            version = cursor.fetchone()
            
            cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
            tables = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            self.audit_results['database_status'] = {
                'connection': '✅ SUCCESS',
                'version': version[0] if version else 'Unknown',
                'tables_count': len(tables),
                'tables': [table[0] for table in tables]
            }
            
            self.audit_results['passed_checks'].append("Veritabanı bağlantısı başarılı")
            
            return self.audit_results['database_status']
            
        except Exception as e:
            error_msg = f"Veritabanı bağlantı hatası: {e}"
            self.audit_results['critical_errors'].append(error_msg)
            self.audit_results['database_status'] = {'connection': f'❌ FAILED: {e}'}
            return self.audit_results['database_status']
    
    async def audit_solana_connectivity(self) -> Dict[str, Any]:
        """Solana RPC bağlantısını test et"""
        logger.info("🔍 Solana RPC bağlantısı test ediliyor...")
        
        rpc_endpoints = [
            'https://api.mainnet-beta.solana.com',
            'https://solana-mainnet.g.alchemy.com/v2/demo',
            'https://api.devnet.solana.com'
        ]
        
        solana_status = {}
        
        for endpoint in rpc_endpoints:
            try:
                async with aiohttp.ClientSession() as session:
                    payload = {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "getHealth"
                    }
                    
                    async with session.post(endpoint, json=payload, timeout=10) as response:
                        if response.status == 200:
                            data = await response.json()
                            solana_status[endpoint] = "✅ HEALTHY"
                            self.audit_results['passed_checks'].append(f"Solana RPC erişilebilir: {endpoint}")
                        else:
                            solana_status[endpoint] = f"❌ HTTP {response.status}"
                            self.audit_results['warnings'].append(f"Solana RPC sorunlu: {endpoint}")
                            
            except Exception as e:
                solana_status[endpoint] = f"❌ ERROR: {e}"
                self.audit_results['warnings'].append(f"Solana RPC hatası: {endpoint} - {e}")
        
        self.audit_results['api_status']['solana_rpc'] = solana_status
        return solana_status
    
    async def audit_external_apis(self) -> Dict[str, Any]:
        """Harici API'leri test et"""
        logger.info("🔍 Harici API'ler test ediliyor...")
        
        apis_to_test = {
            'dexscreener': 'https://api.dexscreener.com/latest/dex/tokens/So11111111111111111111111111111111111111112',
            'raydium_info': 'https://api.raydium.io/v2/sdk/info',
            'jupiter_quote': 'https://quote-api.jup.ag/v6/quote?inputMint=So11111111111111111111111111111111111111112&outputMint=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v&amount=100000000'
        }
        
        api_status = {}
        
        for api_name, url in apis_to_test.items():
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=15) as response:
                        if response.status == 200:
                            data = await response.json()
                            api_status[api_name] = "✅ ACCESSIBLE"
                            self.audit_results['passed_checks'].append(f"API erişilebilir: {api_name}")
                        else:
                            api_status[api_name] = f"❌ HTTP {response.status}"
                            self.audit_results['warnings'].append(f"API sorunlu: {api_name}")
                            
            except Exception as e:
                api_status[api_name] = f"❌ ERROR: {e}"
                self.audit_results['warnings'].append(f"API hatası: {api_name} - {e}")
        
        self.audit_results['api_status']['external_apis'] = api_status
        return api_status
    
    def audit_flask_routes(self) -> Dict[str, Any]:
        """Flask route'larını kontrol et"""
        logger.info("🔍 Flask route'ları kontrol ediliyor...")
        
        try:
            # app.py'yi import et ve route'ları kontrol et
            sys.path.insert(0, '.')
            import app
            
            routes = []
            for rule in app.app.url_map.iter_rules():
                routes.append({
                    'endpoint': rule.endpoint,
                    'methods': list(rule.methods),
                    'rule': str(rule)
                })
            
            critical_routes = [
                '/', '/login', '/wallets', '/token-creator', 
                '/strategies', '/api/wallets', '/api/create_token'
            ]
            
            route_status = {}
            existing_routes = [route['rule'] for route in routes]
            
            for critical_route in critical_routes:
                if critical_route in existing_routes:
                    route_status[critical_route] = "✅ DEFINED"
                    self.audit_results['passed_checks'].append(f"Route tanımlı: {critical_route}")
                else:
                    route_status[critical_route] = "❌ MISSING"
                    self.audit_results['critical_errors'].append(f"Route eksik: {critical_route}")
            
            self.audit_results['integration_status']['flask_routes'] = {
                'total_routes': len(routes),
                'critical_routes_status': route_status,
                'all_routes': routes
            }
            
            return route_status
            
        except Exception as e:
            error_msg = f"Flask route kontrolü hatası: {e}"
            self.audit_results['critical_errors'].append(error_msg)
            return {'error': error_msg}
    
    def audit_security_configuration(self) -> Dict[str, Any]:
        """Güvenlik yapılandırmasını kontrol et"""
        logger.info("🔍 Güvenlik yapılandırması kontrol ediliyor...")
        
        security_checks = {
            'session_secret_set': bool(os.environ.get('SESSION_SECRET')),
            'database_ssl': 'sslmode=require' in os.environ.get('DATABASE_URL', ''),
            'debug_mode_off': not os.environ.get('FLASK_DEBUG', '').lower() in ['true', '1'],
            'encryption_key_exists': os.path.exists('.encryption_key')
        }
        
        security_status = {}
        for check, passed in security_checks.items():
            if passed:
                security_status[check] = "✅ SECURE"
                self.audit_results['passed_checks'].append(f"Güvenlik kontrolü geçti: {check}")
            else:
                security_status[check] = "⚠️ NEEDS_ATTENTION"
                self.audit_results['warnings'].append(f"Güvenlik uyarısı: {check}")
        
        self.audit_results['security_status'] = security_status
        return security_status
    
    def audit_javascript_integration(self) -> Dict[str, Any]:
        """JavaScript entegrasyonlarını kontrol et"""
        logger.info("🔍 JavaScript entegrasyonları kontrol ediliyor...")
        
        js_files = [
            'static/js/main.js',
            'static/js/wallet-functions.js', 
            'static/js/enhanced-token-creator.js'
        ]
        
        js_status = {}
        
        for js_file in js_files:
            if os.path.exists(js_file):
                with open(js_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Critical JavaScript functions check
                critical_functions = [
                    'loadWallets', 'createToken', 'executeStrategy', 
                    'updateBalance', 'displayError', 'displaySuccess'
                ]
                
                found_functions = []
                for func in critical_functions:
                    if func in content:
                        found_functions.append(func)
                
                js_status[js_file] = {
                    'exists': True,
                    'size': len(content),
                    'critical_functions_found': found_functions,
                    'missing_functions': [f for f in critical_functions if f not in found_functions]
                }
                
                if len(found_functions) >= len(critical_functions) * 0.7:  # 70% coverage
                    self.audit_results['passed_checks'].append(f"JavaScript dosyası yeterli: {js_file}")
                else:
                    self.audit_results['warnings'].append(f"JavaScript dosyasında eksik fonksiyonlar: {js_file}")
            else:
                js_status[js_file] = {'exists': False}
                self.audit_results['warnings'].append(f"JavaScript dosyası eksik: {js_file}")
        
        self.audit_results['integration_status']['javascript'] = js_status
        return js_status
    
    async def run_comprehensive_audit(self) -> Dict[str, Any]:
        """Kapsamlı audit'i çalıştır"""
        logger.info("🚀 KAPSAMLI SİSTEM AUDİTİ BAŞLIYOR...")
        
        # 1. Python imports
        import_status = self.audit_python_imports()
        
        # 2. Environment variables  
        env_status = self.audit_environment_variables()
        
        # 3. File structure
        file_status = self.audit_file_structure()
        
        # 4. Database connectivity
        db_status = await self.audit_database_connectivity()
        
        # 5. Solana connectivity
        solana_status = await self.audit_solana_connectivity()
        
        # 6. External APIs
        api_status = await self.audit_external_apis()
        
        # 7. Flask routes
        route_status = self.audit_flask_routes()
        
        # 8. Security configuration
        security_status = self.audit_security_configuration()
        
        # 9. JavaScript integration
        js_status = self.audit_javascript_integration()
        
        return self.audit_results
    
    def generate_final_report(self) -> str:
        """Final raporu oluştur"""
        logger.info("📊 Final rapor oluşturuluyor...")
        
        report = """
🔥 WASHBOT FINAL DEPLOY AUDIT RAPORU
=====================================

GENEL DURUM:
"""
        
        total_checks = (len(self.audit_results['passed_checks']) + 
                       len(self.audit_results['warnings']) + 
                       len(self.audit_results['critical_errors']))
        
        if len(self.audit_results['critical_errors']) == 0:
            if len(self.audit_results['warnings']) == 0:
                report += "🟢 TÜM KONTROLLER BAŞARILI - DEPLOY READy!\n\n"
            else:
                report += "🟡 UYARILAR VAR AMA DEPLOY EDİLEBİLİR\n\n"
        else:
            report += "🔴 KRİTİK HATALAR VAR - DEPLOY EDİLMEMELİ!\n\n"
        
        report += f"Toplam Kontrol: {total_checks}\n"
        report += f"✅ Başarılı: {len(self.audit_results['passed_checks'])}\n"
        report += f"⚠️ Uyarı: {len(self.audit_results['warnings'])}\n"
        report += f"❌ Kritik Hata: {len(self.audit_results['critical_errors'])}\n\n"
        
        if self.audit_results['critical_errors']:
            report += "🔴 KRİTİK HATALAR:\n"
            for error in self.audit_results['critical_errors']:
                report += f"- {error}\n"
            report += "\n"
        
        if self.audit_results['warnings']:
            report += "⚠️ UYARILAR:\n"
            for warning in self.audit_results['warnings']:
                report += f"- {warning}\n"
            report += "\n"
        
        report += "✅ BAŞARILI KONTROLLER:\n"
        for check in self.audit_results['passed_checks']:
            report += f"- {check}\n"
        
        report += "\n"
        report += "📊 DETAYLI DURUM:\n"
        report += f"🗄️ Veritabanı: {self.audit_results['database_status'].get('connection', 'Kontrol edilmedi')}\n"
        report += f"🔗 API Durumu: {len([k for k, v in self.audit_results.get('api_status', {}).get('external_apis', {}).items() if '✅' in str(v)])} API erişilebilir\n"
        report += f"🛡️ Güvenlik: {len([k for k, v in self.audit_results.get('security_status', {}).items() if '✅' in str(v)])} güvenlik kontrolü geçti\n"
        
        return report

async def main():
    """Ana audit fonksiyonu"""
    auditor = FinalDeployAudit()
    
    print("🔥 WASHBOT FINAL DEPLOY AUDIT BAŞLIYOR...")
    print("=" * 50)
    
    # Kapsamlı audit çalıştır
    results = await auditor.run_comprehensive_audit()
    
    # Final raporu oluştur ve göster
    report = auditor.generate_final_report()
    print(report)
    
    # Raporu dosyaya kaydet
    with open('FINAL_DEPLOY_AUDIT_REPORT.txt', 'w', encoding='utf-8') as f:
        f.write(report)
        f.write(f"\n\nDetaylı Sonuçlar:\n{json.dumps(results, indent=2, ensure_ascii=False)}")
    
    print(f"\n📄 Detaylı rapor kaydedildi: FINAL_DEPLOY_AUDIT_REPORT.txt")
    
    # Deploy kararı
    if len(results['critical_errors']) == 0:
        print("\n🚀 SİSTEM DEPLOY İÇİN HAZIR!")
        return True
    else:
        print("\n⛔ SİSTEMDE KRİTİK HATALAR VAR - DEPLOY EDİLMEMELİ!")
        return False

if __name__ == "__main__":
    deploy_ready = asyncio.run(main())
    sys.exit(0 if deploy_ready else 1)