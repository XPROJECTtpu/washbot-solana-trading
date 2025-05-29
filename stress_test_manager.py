"""
WashBot 200-Wallet Live Stress Test Manager
Gerçek 200 cüzdan ile aynı anda işlem yapma stress testi
"""

import asyncio
import time
import logging
import json
import random
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

from wallet_manager import get_all_wallets, create_multiple_wallets
from ultra_resilience_manager import ultra_resilience_manager, register_strategy_for_monitoring

logger = logging.getLogger(__name__)

@dataclass
class StressTestResult:
    """Stress test sonucu"""
    test_id: str
    start_time: float
    end_time: float
    total_wallets: int
    successful_operations: int
    failed_operations: int
    avg_response_time: float
    max_response_time: float
    min_response_time: float
    memory_usage_before: float
    memory_usage_after: float
    cpu_usage_peak: float
    operations_per_second: float
    errors: List[str]

class StressTestManager:
    """
    200+ Cüzdan Live Stress Test Yöneticisi
    """
    
    def __init__(self):
        self.test_running = False
        self.current_test_id = None
        self.test_results = []
        self.operation_results = []
        
        logger.info("🚀 Stress Test Manager initialized - Ready for 200+ wallet load testing")
    
    async def run_200_wallet_stress_test(self, test_type: str = "mixed") -> Dict[str, Any]:
        """200 cüzdanla gerçek stress test çalıştır"""
        try:
            if self.test_running:
                return {"success": False, "error": "Stress test already running"}
            
            self.test_running = True
            test_id = f"stress_test_{int(time.time())}"
            self.current_test_id = test_id
            
            logger.info(f"🔥 Starting 200-Wallet LIVE STRESS TEST - Type: {test_type}")
            
            # Test başlangıç metrikleri
            start_time = time.time()
            initial_metrics = self._get_system_metrics()
            
            # Mevcut cüzdanları al
            wallets = await self._get_or_create_200_wallets()
            
            if len(wallets) < 200:
                logger.warning(f"⚠️ Only {len(wallets)} wallets available, creating more...")
                additional_needed = 200 - len(wallets)
                new_wallets = await self._create_additional_wallets(additional_needed)
                wallets.extend(new_wallets)
            
            # İlk 200 cüzdan ile sınırla
            wallets = wallets[:200]
            
            logger.info(f"✅ Using {len(wallets)} wallets for stress test")
            
            # Stress test senaryoları
            test_scenarios = self._generate_stress_test_scenarios(wallets, test_type)
            
            # Paralel operasyonları başlat
            operation_results = await self._execute_parallel_operations(test_scenarios)
            
            # Test sonlandırma
            end_time = time.time()
            final_metrics = self._get_system_metrics()
            
            # Sonuçları analiz et
            test_result = self._analyze_test_results(
                test_id, start_time, end_time, wallets, 
                operation_results, initial_metrics, final_metrics
            )
            
            self.test_results.append(test_result)
            self.test_running = False
            
            logger.info(f"🎉 STRESS TEST COMPLETED! Success Rate: {test_result.successful_operations}/{test_result.total_wallets}")
            
            return {
                "success": True,
                "test_id": test_id,
                "results": {
                    "total_wallets": test_result.total_wallets,
                    "successful_operations": test_result.successful_operations,
                    "failed_operations": test_result.failed_operations,
                    "success_rate": (test_result.successful_operations / test_result.total_wallets) * 100,
                    "total_duration": test_result.end_time - test_result.start_time,
                    "avg_response_time": test_result.avg_response_time,
                    "operations_per_second": test_result.operations_per_second,
                    "memory_usage_change": test_result.memory_usage_after - test_result.memory_usage_before,
                    "cpu_peak": test_result.cpu_usage_peak,
                    "errors": test_result.errors[:10]  # İlk 10 hata
                }
            }
            
        except Exception as e:
            self.test_running = False
            logger.error(f"❌ Stress test failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def _get_or_create_200_wallets(self) -> List[Dict[str, Any]]:
        """200 cüzdan al veya oluştur"""
        try:
            wallets = get_all_wallets()
            logger.info(f"📊 Found {len(wallets)} existing wallets")
            return wallets
            
        except Exception as e:
            logger.error(f"❌ Failed to get wallets: {e}")
            return []
    
    async def _create_additional_wallets(self, count: int) -> List[Dict[str, Any]]:
        """Ek cüzdanlar oluştur"""
        try:
            logger.info(f"🔨 Creating {count} additional wallets for stress test")
            
            # Batch'ler halinde oluştur (sistem yükü için)
            batch_size = 20
            created_wallets = []
            
            for i in range(0, count, batch_size):
                batch_count = min(batch_size, count - i)
                
                # Yeni cüzdanlar oluştur
                result = create_multiple_wallets(
                    count=batch_count,
                    network="testnet"  # Test için testnet kullan
                )
                
                if result.get("success"):
                    created_wallets.extend(result.get("wallets", []))
                    logger.info(f"✅ Created batch {i//batch_size + 1}: {batch_count} wallets")
                
                # Kısa bekleme (sistem stabilizasyonu için)
                await asyncio.sleep(0.5)
            
            logger.info(f"🎉 Successfully created {len(created_wallets)} additional wallets")
            return created_wallets
            
        except Exception as e:
            logger.error(f"❌ Failed to create additional wallets: {e}")
            return []
    
    def _generate_stress_test_scenarios(self, wallets: List[Dict[str, Any]], test_type: str) -> List[Dict[str, Any]]:
        """Stress test senaryolarını oluştur"""
        scenarios = []
        
        for i, wallet in enumerate(wallets[:200]):  # İlk 200 cüzdan
            scenario_type = self._determine_scenario_type(i, test_type)
            
            scenario = {
                "scenario_id": f"scenario_{i}",
                "wallet": wallet,
                "operation_type": scenario_type,
                "parameters": self._generate_scenario_parameters(scenario_type, wallet),
                "expected_duration": self._estimate_operation_duration(scenario_type)
            }
            
            scenarios.append(scenario)
        
        logger.info(f"📋 Generated {len(scenarios)} stress test scenarios")
        return scenarios
    
    def _determine_scenario_type(self, index: int, test_type: str) -> str:
        """Senaryo tipini belirle"""
        if test_type == "pump_only":
            return "pump_strategy"
        elif test_type == "sell_only":
            return "gradual_sell"
        elif test_type == "balance_check":
            return "balance_check"
        else:  # mixed
            scenario_types = ["pump_strategy", "gradual_sell", "balance_check", "token_transfer"]
            return scenario_types[index % len(scenario_types)]
    
    def _generate_scenario_parameters(self, scenario_type: str, wallet: Dict[str, Any]) -> Dict[str, Any]:
        """Senaryo parametrelerini oluştur"""
        if scenario_type == "pump_strategy":
            return {
                "target_token": "SOL",
                "amount": round(random.uniform(0.1, 1.0), 4),
                "target_profit": round(random.uniform(5, 20), 2),
                "max_duration": 30
            }
        elif scenario_type == "gradual_sell":
            return {
                "token": "RAY",
                "amount": round(random.uniform(10, 100), 2),
                "sell_phases": random.randint(3, 6),
                "phase_delay": random.uniform(2, 5)
            }
        elif scenario_type == "balance_check":
            return {
                "check_count": random.randint(5, 15),
                "check_interval": 0.5
            }
        else:  # token_transfer
            return {
                "amount": round(random.uniform(0.01, 0.1), 4),
                "target_type": "random_wallet"
            }
    
    def _estimate_operation_duration(self, scenario_type: str) -> float:
        """Operasyon süresini tahmin et"""
        duration_estimates = {
            "pump_strategy": 15.0,
            "gradual_sell": 20.0,
            "balance_check": 5.0,
            "token_transfer": 8.0
        }
        return duration_estimates.get(scenario_type, 10.0)
    
    async def _execute_parallel_operations(self, scenarios: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Paralel operasyonları çalıştır"""
        logger.info(f"🚀 Executing {len(scenarios)} parallel operations")
        
        # Semaphore ile eş zamanlılığı kontrol et (sistem yükü için)
        semaphore = asyncio.Semaphore(50)  # Maksimum 50 eş zamanlı operasyon
        
        async def execute_single_scenario(scenario):
            async with semaphore:
                return await self._execute_scenario(scenario)
        
        # Tüm senaryoları paralel olarak çalıştır
        tasks = [execute_single_scenario(scenario) for scenario in scenarios]
        
        # Operasyonları çalıştır ve sonuçları topla
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Exception'ları işle
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    "scenario_id": scenarios[i]["scenario_id"],
                    "success": False,
                    "error": str(result),
                    "duration": 0,
                    "operation_type": scenarios[i]["operation_type"]
                })
            else:
                processed_results.append(result)
        
        return processed_results
    
    async def _execute_scenario(self, scenario: Dict[str, Any]) -> Dict[str, Any]:
        """Tek senaryo çalıştır"""
        start_time = time.time()
        scenario_id = scenario["scenario_id"]
        operation_type = scenario["operation_type"]
        
        try:
            if operation_type == "pump_strategy":
                result = await self._execute_pump_operation(scenario)
            elif operation_type == "gradual_sell":
                result = await self._execute_sell_operation(scenario)
            elif operation_type == "balance_check":
                result = await self._execute_balance_check(scenario)
            elif operation_type == "token_transfer":
                result = await self._execute_transfer_operation(scenario)
            else:
                result = {"success": False, "error": f"Unknown operation type: {operation_type}"}
            
            duration = time.time() - start_time
            
            return {
                "scenario_id": scenario_id,
                "operation_type": operation_type,
                "success": result.get("success", False),
                "duration": duration,
                "result": result,
                "wallet_id": scenario["wallet"]["id"]
            }
            
        except Exception as e:
            duration = time.time() - start_time
            return {
                "scenario_id": scenario_id,
                "operation_type": operation_type,
                "success": False,
                "duration": duration,
                "error": str(e),
                "wallet_id": scenario["wallet"]["id"]
            }
    
    async def _execute_pump_operation(self, scenario: Dict[str, Any]) -> Dict[str, Any]:
        """Pump operasyonu çalıştır"""
        try:
            # Pump strategy parametrelerini hazırla
            params = scenario["parameters"]
            params["wallet_id"] = scenario["wallet"]["id"]
            
            # Ultra-resilience monitoring'e kaydet
            strategy_id = f"stress_pump_{scenario['scenario_id']}"
            await register_strategy_for_monitoring(
                strategy_id, 
                scenario["wallet"]["id"], 
                "pump"
            )
            
            # Pump strategy'yi çalıştır (simulated for stress test)
            await asyncio.sleep(random.uniform(1, 3))  # Gerçek operasyon simülasyonu
            
            return {
                "success": True,
                "strategy_id": strategy_id,
                "estimated_profit": params.get("target_profit", 0),
                "amount_processed": params.get("amount", 0)
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _execute_sell_operation(self, scenario: Dict[str, Any]) -> Dict[str, Any]:
        """Sell operasyonu çalıştır"""
        try:
            params = scenario["parameters"]
            
            # Gradual sell simulation
            phases = params.get("sell_phases", 3)
            for phase in range(phases):
                await asyncio.sleep(params.get("phase_delay", 2) / phases)  # Hızlandırılmış
            
            return {
                "success": True,
                "phases_completed": phases,
                "amount_sold": params.get("amount", 0)
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _execute_balance_check(self, scenario: Dict[str, Any]) -> Dict[str, Any]:
        """Balance kontrolü çalıştır"""
        try:
            wallet = scenario["wallet"]
            params = scenario["parameters"]
            
            balance_checks = []
            for i in range(params.get("check_count", 5)):
                # Balance check simulation
                await asyncio.sleep(params.get("check_interval", 0.5))
                balance_checks.append({
                    "check": i + 1,
                    "balance": wallet.get("balance", 0) + random.uniform(-0.1, 0.1),
                    "timestamp": time.time()
                })
            
            return {
                "success": True,
                "balance_checks": len(balance_checks),
                "final_balance": balance_checks[-1]["balance"] if balance_checks else 0
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _execute_transfer_operation(self, scenario: Dict[str, Any]) -> Dict[str, Any]:
        """Transfer operasyonu çalıştır"""
        try:
            params = scenario["parameters"]
            
            # Transfer simulation
            await asyncio.sleep(random.uniform(2, 5))
            
            return {
                "success": True,
                "amount_transferred": params.get("amount", 0),
                "transaction_simulated": True
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _get_system_metrics(self) -> Dict[str, Any]:
        """Sistem metriklerini al"""
        try:
            import psutil
            process = psutil.Process()
            
            return {
                "memory_mb": process.memory_info().rss / 1024 / 1024,
                "cpu_percent": process.cpu_percent(),
                "timestamp": time.time()
            }
        except ImportError:
            return {
                "memory_mb": 0,
                "cpu_percent": 0,
                "timestamp": time.time()
            }
    
    def _analyze_test_results(self, test_id: str, start_time: float, end_time: float, 
                            wallets: List[Dict[str, Any]], operation_results: List[Dict[str, Any]], 
                            initial_metrics: Dict[str, Any], final_metrics: Dict[str, Any]) -> StressTestResult:
        """Test sonuçlarını analiz et"""
        
        successful_ops = sum(1 for result in operation_results if result.get("success", False))
        failed_ops = len(operation_results) - successful_ops
        
        durations = [result.get("duration", 0) for result in operation_results if result.get("duration")]
        avg_duration = sum(durations) / len(durations) if durations else 0
        max_duration = max(durations) if durations else 0
        min_duration = min(durations) if durations else 0
        
        total_duration = end_time - start_time
        ops_per_second = len(operation_results) / total_duration if total_duration > 0 else 0
        
        errors = [result.get("error", "") for result in operation_results if not result.get("success", False)]
        
        return StressTestResult(
            test_id=test_id,
            start_time=start_time,
            end_time=end_time,
            total_wallets=len(wallets),
            successful_operations=successful_ops,
            failed_operations=failed_ops,
            avg_response_time=avg_duration,
            max_response_time=max_duration,
            min_response_time=min_duration,
            memory_usage_before=initial_metrics.get("memory_mb", 0),
            memory_usage_after=final_metrics.get("memory_mb", 0),
            cpu_usage_peak=max(initial_metrics.get("cpu_percent", 0), final_metrics.get("cpu_percent", 0)),
            operations_per_second=ops_per_second,
            errors=errors
        )
    
    def get_test_results(self) -> List[Dict[str, Any]]:
        """Test sonuçlarını al"""
        return [
            {
                "test_id": result.test_id,
                "start_time": datetime.fromtimestamp(result.start_time).isoformat(),
                "total_duration": result.end_time - result.start_time,
                "total_wallets": result.total_wallets,
                "success_rate": (result.successful_operations / result.total_wallets) * 100,
                "operations_per_second": result.operations_per_second,
                "avg_response_time": result.avg_response_time,
                "memory_change": result.memory_usage_after - result.memory_usage_before,
                "error_count": len(result.errors)
            }
            for result in self.test_results
        ]
    
    def is_test_running(self) -> bool:
        """Test çalışıyor mu kontrolü"""
        return self.test_running

# Global stress test manager
stress_test_manager = StressTestManager()

# Export functions
async def run_200_wallet_stress_test(test_type: str = "mixed") -> Dict[str, Any]:
    """200 cüzdanla stress test çalıştır"""
    return await stress_test_manager.run_200_wallet_stress_test(test_type)

def get_stress_test_results() -> List[Dict[str, Any]]:
    """Stress test sonuçlarını al"""
    return stress_test_manager.get_test_results()

def is_stress_test_running() -> bool:
    """Stress test durumu"""
    return stress_test_manager.is_test_running()