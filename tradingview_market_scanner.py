"""
🔥 WASHBOT TRADINGVIEW MARKET SCANNER
Volume Spike & Momentum Detector
Real-time Solana token scanning with TradingView integration
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import json

from tradingview_screener import Scanner, Column
import aiohttp
import time

logger = logging.getLogger(__name__)

class WashBotMarketScanner:
    """
    Advanced market scanner using TradingView data
    Volume Spike Detection + Momentum Analysis
    """
    
    def __init__(self):
        self.scanner = Scanner()
        self.volume_threshold = 3.0  # 3x normal volume
        self.momentum_threshold = 5.0  # 5% price change
        self.scan_interval = 30  # seconds
        self.is_scanning = False
        
        # Hot tokens tracking
        self.hot_tokens = {}
        self.volume_spikes = []
        self.momentum_signals = []
        
        # Scanner configuration
        self.scanner_columns = [
            Column.Fundamental.market_cap_basic,
            Column.Fundamental.volume_24h,
            Column.Performance.perf_1_day,
            Column.Performance.perf_1_hour,
            Column.Tech.volatility,
            Column.Tech.average_volume_10d_calc,
            Column.Fundamental.change_abs,
            Column.Fundamental.change,
        ]
        
        logger.info("🔥 WashBot Market Scanner initialized")
    
    async def start_volume_spike_detector(self) -> None:
        """Volume spike detector başlat"""
        logger.info("📈 Starting Volume Spike Detector...")
        
        self.is_scanning = True
        while self.is_scanning:
            try:
                await self._scan_volume_spikes()
                await asyncio.sleep(self.scan_interval)
            except Exception as e:
                logger.error(f"Volume spike detector error: {e}")
                await asyncio.sleep(5)
    
    async def start_momentum_detector(self) -> None:
        """Momentum detector başlat"""
        logger.info("🚀 Starting Momentum Detector...")
        
        while self.is_scanning:
            try:
                await self._scan_momentum_signals()
                await asyncio.sleep(self.scan_interval)
            except Exception as e:
                logger.error(f"Momentum detector error: {e}")
                await asyncio.sleep(5)
    
    async def _scan_volume_spikes(self) -> List[Dict[str, Any]]:
        """Volume spike'larını tara"""
        try:
            # TradingView screener ile volume analizi
            results = self.scanner.get_scanner_data(
                market='crypto',
                interval='1h',
                columns=self.scanner_columns,
                filters=[
                    ('volume_24h', 'greater', 1000000),  # Min 1M volume
                    ('market_cap_basic', 'greater', 10000000),  # Min 10M market cap
                ]
            )
            
            volume_spikes = []
            current_time = datetime.now()
            
            for token_data in results['data']:
                try:
                    symbol = token_data.get('s', 'UNKNOWN')
                    volume_24h = token_data.get('volume_24h', 0)
                    avg_volume = token_data.get('average_volume_10d_calc', 1)
                    
                    # Volume spike ratio hesapla
                    if avg_volume > 0:
                        volume_ratio = volume_24h / avg_volume
                        
                        if volume_ratio >= self.volume_threshold:
                            spike_data = {
                                'symbol': symbol,
                                'volume_24h': volume_24h,
                                'avg_volume_10d': avg_volume,
                                'volume_ratio': volume_ratio,
                                'market_cap': token_data.get('market_cap_basic', 0),
                                'price_change_24h': token_data.get('change', 0),
                                'detected_at': current_time.isoformat(),
                                'signal_type': 'VOLUME_SPIKE',
                                'strength': min(10, volume_ratio)  # 1-10 strength scale
                            }
                            
                            volume_spikes.append(spike_data)
                            logger.info(f"🔥 VOLUME SPIKE: {symbol} - {volume_ratio:.2f}x normal volume!")
                            
                except Exception as e:
                    logger.error(f"Error processing token data: {e}")
                    continue
            
            # En güçlü spike'ları kaydet
            if volume_spikes:
                self.volume_spikes.extend(volume_spikes)
                # Son 100 spike'ı tut
                self.volume_spikes = self.volume_spikes[-100:]
                
                await self._notify_volume_spikes(volume_spikes)
            
            return volume_spikes
            
        except Exception as e:
            logger.error(f"Volume spike scan error: {e}")
            return []
    
    async def _scan_momentum_signals(self) -> List[Dict[str, Any]]:
        """Momentum sinyallerini tara"""
        try:
            # Momentum için özel filtreler
            results = self.scanner.get_scanner_data(
                market='crypto',
                interval='1h',
                columns=self.scanner_columns,
                filters=[
                    ('change', 'greater', self.momentum_threshold),  # Min %5 artış
                    ('volume_24h', 'greater', 500000),  # Min 500K volume
                    ('volatility', 'greater', 0.02),  # Min %2 volatilite
                ]
            )
            
            momentum_signals = []
            current_time = datetime.now()
            
            for token_data in results['data']:
                try:
                    symbol = token_data.get('s', 'UNKNOWN')
                    price_change = token_data.get('change', 0)
                    price_change_1h = token_data.get('perf_1_hour', 0)
                    volatility = token_data.get('volatility', 0)
                    
                    # Momentum strength hesapla
                    momentum_strength = abs(price_change) + (abs(price_change_1h) * 0.5) + (volatility * 100)
                    
                    if momentum_strength >= 5.0:  # Min momentum threshold
                        signal_data = {
                            'symbol': symbol,
                            'price_change_24h': price_change,
                            'price_change_1h': price_change_1h,
                            'volatility': volatility,
                            'momentum_strength': momentum_strength,
                            'volume_24h': token_data.get('volume_24h', 0),
                            'market_cap': token_data.get('market_cap_basic', 0),
                            'detected_at': current_time.isoformat(),
                            'signal_type': 'MOMENTUM_SIGNAL',
                            'direction': 'BULLISH' if price_change > 0 else 'BEARISH'
                        }
                        
                        momentum_signals.append(signal_data)
                        direction_emoji = "🚀" if price_change > 0 else "📉"
                        logger.info(f"{direction_emoji} MOMENTUM: {symbol} - {price_change:.2f}% (Strength: {momentum_strength:.2f})")
                        
                except Exception as e:
                    logger.error(f"Error processing momentum data: {e}")
                    continue
            
            # Momentum sinyalleri kaydet
            if momentum_signals:
                self.momentum_signals.extend(momentum_signals)
                # Son 100 sinyali tut
                self.momentum_signals = self.momentum_signals[-100:]
                
                await self._notify_momentum_signals(momentum_signals)
            
            return momentum_signals
            
        except Exception as e:
            logger.error(f"Momentum scan error: {e}")
            return []
    
    async def _notify_volume_spikes(self, spikes: List[Dict[str, Any]]) -> None:
        """Volume spike bildirimleri"""
        for spike in spikes:
            if spike['volume_ratio'] >= 5.0:  # Super spike
                logger.warning(f"🚨 SUPER VOLUME SPIKE: {spike['symbol']} - {spike['volume_ratio']:.1f}x NORMAL!")
            
            # Hot tokens listesine ekle
            self.hot_tokens[spike['symbol']] = {
                'last_seen': datetime.now(),
                'spike_strength': spike['volume_ratio'],
                'signal_type': 'volume_spike'
            }
    
    async def _notify_momentum_signals(self, signals: List[Dict[str, Any]]) -> None:
        """Momentum sinyal bildirimleri"""
        for signal in signals:
            if signal['momentum_strength'] >= 10.0:  # Strong momentum
                direction = signal['direction']
                logger.warning(f"⚡ STRONG MOMENTUM: {signal['symbol']} {direction} - Strength: {signal['momentum_strength']:.1f}")
            
            # Hot tokens listesine ekle
            self.hot_tokens[signal['symbol']] = {
                'last_seen': datetime.now(),
                'momentum_strength': signal['momentum_strength'],
                'signal_type': 'momentum',
                'direction': signal['direction']
            }
    
    def get_hot_tokens(self, limit: int = 20) -> List[Dict[str, Any]]:
        """En aktif token'ları getir"""
        # Son 1 saat içindeki hot tokens
        cutoff_time = datetime.now() - timedelta(hours=1)
        
        hot_list = []
        for symbol, data in self.hot_tokens.items():
            if data['last_seen'] > cutoff_time:
                hot_list.append({
                    'symbol': symbol,
                    'signal_type': data['signal_type'],
                    'strength': data.get('spike_strength', data.get('momentum_strength', 0)),
                    'direction': data.get('direction', 'NEUTRAL'),
                    'last_seen': data['last_seen'].isoformat()
                })
        
        # Strength'e göre sırala
        hot_list.sort(key=lambda x: x['strength'], reverse=True)
        return hot_list[:limit]
    
    def get_recent_signals(self, signal_type: str = 'all', limit: int = 50) -> List[Dict[str, Any]]:
        """Son sinyalleri getir"""
        if signal_type == 'volume':
            return self.volume_spikes[-limit:]
        elif signal_type == 'momentum':
            return self.momentum_signals[-limit:]
        else:
            # Tüm sinyaller birleştirilmiş
            all_signals = self.volume_spikes + self.momentum_signals
            all_signals.sort(key=lambda x: x['detected_at'], reverse=True)
            return all_signals[:limit]
    
    def stop_scanning(self) -> None:
        """Tarama durdur"""
        self.is_scanning = False
        logger.info("🛑 Market scanning stopped")
    
    async def get_token_analysis(self, symbol: str) -> Dict[str, Any]:
        """Belirli bir token için detaylı analiz"""
        try:
            # Token'ın recent activity'sini kontrol et
            volume_history = [s for s in self.volume_spikes if s['symbol'] == symbol]
            momentum_history = [s for s in self.momentum_signals if s['symbol'] == symbol]
            
            analysis = {
                'symbol': symbol,
                'is_hot': symbol in self.hot_tokens,
                'volume_spike_count_24h': len([v for v in volume_history if 
                    datetime.fromisoformat(v['detected_at']) > datetime.now() - timedelta(hours=24)]),
                'momentum_signal_count_24h': len([m for m in momentum_history if 
                    datetime.fromisoformat(m['detected_at']) > datetime.now() - timedelta(hours=24)]),
                'recent_volume_spikes': volume_history[-5:],
                'recent_momentum_signals': momentum_history[-5:],
                'overall_activity': 'HIGH' if symbol in self.hot_tokens else 'NORMAL'
            }
            
            return analysis
            
        except Exception as e:
            logger.error(f"Token analysis error for {symbol}: {e}")
            return {'symbol': symbol, 'error': str(e)}

# Global scanner instance
market_scanner = WashBotMarketScanner()

async def start_market_scanning() -> None:
    """Market tarama başlat"""
    logger.info("🚀 Starting WashBot Market Scanner...")
    
    # Volume spike ve momentum detector'ları paralel başlat
    tasks = [
        market_scanner.start_volume_spike_detector(),
        market_scanner.start_momentum_detector()
    ]
    
    await asyncio.gather(*tasks)

def get_scanner_status() -> Dict[str, Any]:
    """Scanner durumu"""
    return {
        'is_scanning': market_scanner.is_scanning,
        'hot_tokens_count': len(market_scanner.hot_tokens),
        'volume_spikes_today': len([s for s in market_scanner.volume_spikes if 
            datetime.fromisoformat(s['detected_at']).date() == datetime.now().date()]),
        'momentum_signals_today': len([s for s in market_scanner.momentum_signals if 
            datetime.fromisoformat(s['detected_at']).date() == datetime.now().date()]),
        'last_scan': datetime.now().isoformat()
    }

if __name__ == "__main__":
    # Test scanning
    asyncio.run(start_market_scanning())