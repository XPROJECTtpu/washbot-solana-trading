"""
🔥 WASHBOT COMPLETE SYSTEM DNA AUDIT 
Her satır, her nokta virgül, her entegrasyon kontrol edilecek
"""

import os
import json
import time
from datetime import datetime

class WashBotSystemAudit:
    """Tam sistem DNA kontrolü"""
    
    def __init__(self):
        self.audit_results = {
            'timestamp': datetime.now().isoformat(),
            'critical_errors': [],
            'warnings': [],
            'optimizations': [],
            'status': 'SCANNING'
        }
    
    def audit_frontend_integrity(self):
        """Frontend entegrasyonu kontrol"""
        issues = []
        
        # Token Creator Template Kontrolü
        token_creator_path = 'templates/token_creator.html'
        if os.path.exists(token_creator_path):
            with open(token_creator_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Token İkonu konumu kontrolü
                if 'Token İkonu' not in content:
                    issues.append("❌ Token İkonu bölümü bulunamadı")
                
                # Transfer ücretleri kontrolü
                if 'transferFeeEnabled' not in content:
                    issues.append("❌ Transfer ücretleri sistemi eksik")
                
                # Wallet seçimi kontrolü
                if 'walletSelect' not in content:
                    issues.append("❌ Wallet seçimi eksik")
                
                # JavaScript entegrasyonu
                if 'handleIconPreview' not in content:
                    issues.append("❌ İkon önizleme JavaScript eksik")
        else:
            issues.append("🚨 CRITICAL: Token Creator template bulunamadı")
        
        return issues
    
    def audit_backend_apis(self):
        """Backend API entegrasyonu kontrol"""
        issues = []
        
        # app.py kontrolü
        app_path = 'app.py'
        if os.path.exists(app_path):
            with open(app_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Token creation API
                if '/api/create-token' not in content:
                    issues.append("❌ Token creation API eksik")
                
                # Transfer fee support
                if 'transfer_fee_enabled' not in content:
                    issues.append("❌ Transfer fee backend desteği eksik")
                
                # Wallet management
                if '/api/wallets' not in content:
                    issues.append("❌ Wallet API eksik")
                
                # Enhanced strategies
                if 'enhanced_pump_strategy' not in content:
                    issues.append("❌ Enhanced pump strategies eksik")
        else:
            issues.append("🚨 CRITICAL: app.py bulunamadı")
        
        return issues
    
    def audit_solana_integrations(self):
        """Solana entegrasyonları kontrol"""
        issues = []
        
        # Solana utils kontrolü
        solana_files = [
            'solana_utils.py',
            'solana_trading_bot.py', 
            'raydium_client.py',
            'solana_token_creator.py'
        ]
        
        for file in solana_files:
            if not os.path.exists(file):
                issues.append(f"⚠️ {file} bulunamadı")
        
        return issues
    
    def audit_database_models(self):
        """Database model kontrolü"""
        issues = []
        
        models_path = 'models.py'
        if os.path.exists(models_path):
            with open(models_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Essential models check
                required_models = ['User', 'Wallet', 'Token', 'OperationLog']
                for model in required_models:
                    if f'class {model}' not in content:
                        issues.append(f"❌ {model} model eksik")
        else:
            issues.append("🚨 CRITICAL: models.py bulunamadı")
        
        return issues
    
    def audit_security_systems(self):
        """Güvenlik sistemleri kontrol"""
        issues = []
        
        security_path = 'security.py'
        if os.path.exists(security_path):
            with open(security_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Security features
                security_features = [
                    'encrypt_data',
                    'verify_password', 
                    'generate_2fa_secret',
                    'track_login_attempt'
                ]
                
                for feature in security_features:
                    if feature not in content:
                        issues.append(f"⚠️ {feature} güvenlik fonksiyonu eksik")
        else:
            issues.append("⚠️ security.py bulunamadı")
        
        return issues
    
    def audit_trading_engines(self):
        """Trading engine kontrolü"""
        issues = []
        
        trading_files = [
            'advanced_trading_engine.py',
            'enhanced_pump_dump_strategies.py',
            'strategies.py'
        ]
        
        for file in trading_files:
            if os.path.exists(file):
                with open(file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    if 'async def' not in content:
                        issues.append(f"⚠️ {file} async functions eksik")
                    
                    if 'class' not in content:
                        issues.append(f"⚠️ {file} class definitions eksik")
            else:
                issues.append(f"⚠️ {file} bulunamadı")
        
        return issues
    
    def run_complete_audit(self):
        """Tam sistem auditi çalıştır"""
        print("🔥 WASHBOT DNA AUDIT BAŞLADI...")
        
        # Frontend Audit
        print("\n📱 Frontend Kontrolü...")
        frontend_issues = self.audit_frontend_integrity()
        self.audit_results['frontend'] = frontend_issues
        
        # Backend Audit  
        print("🔧 Backend Kontrolü...")
        backend_issues = self.audit_backend_apis()
        self.audit_results['backend'] = backend_issues
        
        # Solana Audit
        print("🌐 Solana Entegrasyonu Kontrolü...")
        solana_issues = self.audit_solana_integrations()
        self.audit_results['solana'] = solana_issues
        
        # Database Audit
        print("🗄️ Database Kontrolü...")
        db_issues = self.audit_database_models()
        self.audit_results['database'] = db_issues
        
        # Security Audit
        print("🔒 Güvenlik Kontrolü...")
        security_issues = self.audit_security_systems()
        self.audit_results['security'] = security_issues
        
        # Trading Engine Audit
        print("⚡ Trading Engine Kontrolü...")
        trading_issues = self.audit_trading_engines()
        self.audit_results['trading'] = trading_issues
        
        # Final Report
        self.generate_final_report()
        
        return self.audit_results
    
    def generate_final_report(self):
        """Final rapor oluştur"""
        total_issues = 0
        critical_count = 0
        
        for category, issues in self.audit_results.items():
            if isinstance(issues, list):
                total_issues += len(issues)
                critical_count += len([i for i in issues if '🚨' in i])
        
        print(f"\n{'='*50}")
        print("🔥 WASHBOT DNA AUDIT SONUÇLARI")
        print(f"{'='*50}")
        print(f"📊 Toplam Kontrol Edilen Kategori: 6")
        print(f"⚠️ Toplam Tespit Edilen Sorun: {total_issues}")
        print(f"🚨 Kritik Sorun: {critical_count}")
        
        if total_issues == 0:
            print("✅ SİSTEM TAMAMEN SAĞLIKLI!")
            self.audit_results['status'] = 'HEALTHY'
        elif critical_count == 0:
            print("🟡 SİSTEM GENEL OLARAK İYİ - KÜÇÜK İYİLEŞTİRMELER GEREKLİ")
            self.audit_results['status'] = 'GOOD_WITH_WARNINGS'
        else:
            print("🔴 KRİTİK SORUNLAR TESPİT EDİLDİ!")
            self.audit_results['status'] = 'NEEDS_CRITICAL_FIXES'
        
        # Detayları yazdır
        for category, issues in self.audit_results.items():
            if isinstance(issues, list) and issues:
                print(f"\n📋 {category.upper()} SORUNLARI:")
                for issue in issues:
                    print(f"  {issue}")

if __name__ == "__main__":
    auditor = WashBotSystemAudit()
    results = auditor.run_complete_audit()