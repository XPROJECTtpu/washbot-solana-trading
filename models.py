from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
import json
from datetime import datetime
import os
import uuid
from flask_login import UserMixin

from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Settings(Base):
    """General settings table"""
    __tablename__ = 'settings'
    
    id = Column(Integer, primary_key=True)
    key = Column(String(64), unique=True, nullable=False)
    value = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<Settings(key='{self.key}')>"

class User(UserMixin, Base):
    """User accounts table"""
    __tablename__ = 'users'
    
    id = Column(String(64), primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    email = Column(String(128), unique=True, nullable=True)
    password_hash = Column(String(256), nullable=False)
    full_name = Column(String(128), nullable=True)
    role = Column(String(32), default='user')  # admin, user
    _is_active = Column('is_active', Boolean, default=True)
    last_login = Column(DateTime, nullable=True)
    
    # 2FA fields
    twofa_enabled = Column(Boolean, default=False)
    twofa_secret = Column(String(32), nullable=True)
    
    # Security settings
    security_config_id = Column(String(64), ForeignKey('security_configs.id'), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @property
    def is_active(self):
        """Return True if the user is active"""
        return self._is_active
    
    # Relationships
    security_config = relationship("SecurityConfig", back_populates="user", uselist=False)
    login_logs = relationship("LoginLog", back_populates="user")
    
    def __repr__(self):
        return f"<User(id='{self.id}', username='{self.username}', role='{self.role}')>"
    
    # Flask-Login required methods
    def get_id(self):
        """Return the user ID as a string, required for Flask-Login"""
        return str(self.id)
    
    @property
    def is_authenticated(self):
        """Always return True for logged-in users"""
        return True
    
    @property
    def is_anonymous(self):
        """Always False for real users"""
        return False
    
    def to_dict(self, include_secrets=False):
        """Return user data as dictionary"""
        last_login = None
        if self.last_login:
            last_login = self.last_login.isoformat()
            
        result = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "role": self.role,
            "is_active": self.is_active,
            "last_login": last_login,
            "twofa_enabled": self.twofa_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }
        
        # Include 2FA secret only when specifically requested
        if include_secrets and self.twofa_secret:
            result["twofa_secret"] = self.twofa_secret
            
        return result

class SecurityConfig(Base):
    """Security configuration per user"""
    __tablename__ = 'security_configs'
    
    id = Column(String(64), primary_key=True)
    user_id = Column(String(64), nullable=False)
    
    # IP restrictions
    ip_whitelist = Column(Text, nullable=True)  # JSON array of allowed IPs/CIDRs
    ip_blacklist = Column(Text, nullable=True)  # JSON array of blocked IPs/CIDRs
    
    # Transaction limits
    daily_limit = Column(Float, default=1000.0)  # SOL
    per_transaction_limit = Column(Float, default=100.0)  # SOL
    require_2fa_for_transactions = Column(Boolean, default=True)
    approval_threshold = Column(Float, default=50.0)  # Transactions over this amount need approval
    
    # Session settings
    max_session_duration = Column(Integer, default=86400)  # 24 hours
    idle_timeout = Column(Integer, default=3600)  # 1 hour
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="security_config")
    
    def __repr__(self):
        return f"<SecurityConfig(id='{self.id}', user_id='{self.user_id}')>"
    
    def get_ip_whitelist(self):
        """Return IP whitelist as Python list"""
        if not self.ip_whitelist:
            return []
        try:
            return json.loads(self.ip_whitelist)
        except:
            return []
    
    def get_ip_blacklist(self):
        """Return IP blacklist as Python list"""
        if not self.ip_blacklist:
            return []
        try:
            return json.loads(self.ip_blacklist)
        except:
            return []
    
    def set_ip_whitelist(self, ip_list):
        """Set IP whitelist from Python list"""
        self.ip_whitelist = json.dumps(ip_list)
    
    def set_ip_blacklist(self, ip_list):
        """Set IP blacklist from Python list"""
        self.ip_blacklist = json.dumps(ip_list)
        
    def to_dict(self):
        """Return security config as dictionary"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "ip_whitelist": self.get_ip_whitelist(),
            "ip_blacklist": self.get_ip_blacklist(),
            "daily_limit": self.daily_limit,
            "per_transaction_limit": self.per_transaction_limit,
            "require_2fa_for_transactions": self.require_2fa_for_transactions,
            "approval_threshold": self.approval_threshold,
            "max_session_duration": self.max_session_duration,
            "idle_timeout": self.idle_timeout,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }

class LoginLog(Base):
    """Login attempts and successful logins log"""
    __tablename__ = 'login_logs'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(String(64), ForeignKey('users.id'), nullable=False)
    ip_address = Column(String(45), nullable=True)  # IPv6 can be up to 45 chars
    user_agent = Column(Text, nullable=True)
    success = Column(Boolean, default=False)
    failure_reason = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="login_logs")
    
    def __repr__(self):
        return f"<LoginLog(id={self.id}, user_id='{self.user_id}', success={self.success})>"
        
    def to_dict(self):
        """Return login log as dictionary"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "success": self.success,
            "failure_reason": self.failure_reason,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class TransactionApproval(Base):
    """Transaction approval requests"""
    __tablename__ = 'transaction_approvals'
    
    id = Column(String(64), primary_key=True)
    user_id = Column(String(64), ForeignKey('users.id'), nullable=False)
    wallet_id = Column(String(64), ForeignKey('wallets.id'), nullable=True)
    transaction_type = Column(String(32), nullable=False)  # swap, transfer, liquidity, etc.
    amount = Column(Float, nullable=False)
    token_address = Column(String(256), nullable=True)  # Null for SOL
    details = Column(Text, nullable=True)  # JSON string with additional details
    
    # Approval status
    status = Column(String(32), default='pending')  # pending, approved, rejected, expired
    approved_by = Column(String(64), nullable=True)  # User ID of approver
    approval_notes = Column(Text, nullable=True)
    requires_2fa = Column(Boolean, default=False)
    verified_with_2fa = Column(Boolean, default=False)
    
    # Related transaction
    transaction_id = Column(Integer, ForeignKey('transactions.id'), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User")
    wallet = relationship("Wallet")
    transaction = relationship("Transaction")
    
    def __repr__(self):
        return f"<TransactionApproval(id='{self.id}', status='{self.status}', amount={self.amount})>"
    
    @property
    def details_dict(self):
        """Return details as dictionary"""
        details_value = self.details
        if not details_value:
            return {}
        try:
            return json.loads(str(details_value))
        except:
            return {}
    
    def is_expired(self):
        """Check if approval request is expired"""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at
    
    def to_dict(self):
        """Return approval request as dictionary"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "wallet_id": self.wallet_id,
            "transaction_type": self.transaction_type,
            "amount": self.amount,
            "token_address": self.token_address,
            "details": self.details_dict,
            "status": self.status,
            "approved_by": self.approved_by,
            "approval_notes": self.approval_notes,
            "requires_2fa": self.requires_2fa,
            "verified_with_2fa": self.verified_with_2fa,
            "transaction_id": self.transaction_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_expired": self.is_expired()
        }

class Wallet(Base):
    """Wallet table"""
    __tablename__ = 'wallets'
    
    id = Column(String(64), primary_key=True)
    address = Column(String(256), unique=True, nullable=False)
    encrypted_private_key = Column(Text, nullable=True)
    private_key = Column(Text, nullable=True)  # For test wallets only
    label = Column(String(128), nullable=True)
    balance = Column(Float, default=0.0)
    network = Column(String(32), default='mainnet-beta')  # Changed to mainnet
    is_main = Column(Boolean, default=False)
    is_test = Column(Boolean, default=False)  # Test cüzdanı
    is_external = Column(Boolean, default=False)  # External imported wallet
    is_strategy_created = Column(Boolean, default=False)  # Created from strategy
    wallet_type = Column(String(32), default='generated')  # generated, imported, hardware
    tags = Column(Text, nullable=True)  # JSON array of tags for organization
    is_global_selectable = Column(Boolean, default=True)  # Can be selected across system
    strategy_id = Column(String(64), nullable=True)  # Strategy that created this wallet
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = Column(String(64), ForeignKey('users.id'), nullable=True)
    
    # Relationships
    token_balances = relationship("TokenBalance", back_populates="wallet")
    transactions = relationship("Transaction", back_populates="wallet")
    liquidity_positions = relationship("LiquidityPosition", back_populates="wallet", foreign_keys="LiquidityPosition.wallet_id")
    
    def __repr__(self):
        return f"<Wallet(id='{self.id}', address='{self.address[:8] if self.address else ''}...', network='{self.network}')>"
    
    def to_dict(self):
        """Return wallet data as dictionary (excluding private key)"""
        created_at = None
        if self.created_at is not None:
            created_at = self.created_at.isoformat()
            
        updated_at = None
        if self.updated_at is not None:
            updated_at = self.updated_at.isoformat()
            
        return {
            "id": self.id,
            "address": self.address,
            "name": self.label,
            "balance": self.balance,
            "network": self.network,
            "is_main_pool": self.is_main,
            "created_at": created_at,
            "updated_at": updated_at
        }

class Token(Base):
    """Token table"""
    __tablename__ = 'tokens'
    
    address = Column(String(256), primary_key=True)  # Token contract address as primary key
    name = Column(String(128), nullable=True)
    symbol = Column(String(32), nullable=True)
    decimals = Column(Integer, default=9)
    network = Column(String(32), default='mainnet-beta')
    creator = Column(String(256), nullable=True)  # Creator wallet address
    creator_wallet_id = Column(String(64), nullable=True)  # Creator wallet ID
    supply = Column(Float, default=0.0)  # Total supply
    icon_url = Column(String(512), nullable=True)  # Token icon URL
    metadata_uri = Column(String(512), nullable=True)  # Metadata URI
    details = Column(Text, nullable=True)  # JSON string for token properties
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    balances = relationship("TokenBalance", back_populates="token", foreign_keys="TokenBalance.token_address")
    prices = relationship("TokenPrice", back_populates="token", foreign_keys="TokenPrice.token_address")
    
    def __repr__(self):
        return f"<Token(symbol='{self.symbol}', address='{self.address[:8]}...', network='{self.network}')>"
    
    def to_dict(self):
        """Return token data as dictionary"""
        created_at = None
        if self.created_at is not None:
            created_at = self.created_at.isoformat()
            
        updated_at = None
        if self.updated_at is not None:
            updated_at = self.updated_at.isoformat()
        
        # Parse JSON details if exists  
        token_details = {}
        if self.details:
            try:
                token_details = json.loads(str(self.details))
            except:
                pass
            
        return {
            "address": self.address,
            "name": self.name,
            "symbol": self.symbol,
            "decimals": self.decimals,
            "network": self.network,
            "creator": self.creator,
            "creator_wallet_id": self.creator_wallet_id,
            "supply": self.supply,
            "icon_url": self.icon_url,
            "metadata_uri": self.metadata_uri,
            "details": token_details,
            "created_at": created_at,
            "updated_at": updated_at
        }

class TokenBalance(Base):
    """Token balance table"""
    __tablename__ = 'token_balances'
    
    id = Column(Integer, primary_key=True)
    wallet_id = Column(String(64), ForeignKey('wallets.id'), nullable=False)
    token_address = Column(String(256), ForeignKey('tokens.address'), nullable=False)
    balance = Column(Float, default=0.0)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    wallet = relationship("Wallet", back_populates="token_balances")
    token = relationship("Token", back_populates="balances")
    
    def __repr__(self):
        return f"<TokenBalance(wallet='{self.wallet_id}', token='{self.token_address[:8]}...', balance={self.balance})>"

class TokenPrice(Base):
    """Token price table"""
    __tablename__ = 'token_prices'
    
    id = Column(Integer, primary_key=True)
    token_address = Column(String(256), ForeignKey('tokens.address'), nullable=False)
    price_usd = Column(Float, nullable=False)
    price_sol = Column(Float, nullable=True)
    volume_24h = Column(Float, nullable=True)
    liquidity_usd = Column(Float, nullable=True)
    market_cap = Column(Float, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source = Column(String(32), default='dexscreener')
    
    # Relationships
    token = relationship("Token", back_populates="prices")
    
    def __repr__(self):
        return f"<TokenPrice(token='{self.token_address[:8]}...', price_usd={self.price_usd}, timestamp='{self.timestamp}')>"

class Transaction(Base):
    """Transaction table"""
    __tablename__ = 'transactions'
    
    id = Column(Integer, primary_key=True)
    txid = Column(String(256), unique=True, nullable=True)
    wallet_id = Column(String(64), ForeignKey('wallets.id'), nullable=False)
    type = Column(String(32), nullable=False)  # swap, transfer, liquidity, airdrop, etc.
    status = Column(String(32), default='pending')  # pending, success, failed
    from_address = Column(String(256), nullable=True)
    to_address = Column(String(256), nullable=True)
    amount = Column(Float, nullable=True)
    token_address = Column(String(256), nullable=True)
    fee = Column(Float, nullable=True)
    network = Column(String(32), default='devnet')
    details = Column(Text, nullable=True)  # JSON string
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    wallet = relationship("Wallet", back_populates="transactions")
    
    def __repr__(self):
        return f"<Transaction(id={self.id}, type='{self.type}', status='{self.status}', wallet='{self.wallet_id}')>"
    
    @property
    def details_dict(self):
        """Return details as dictionary"""
        details_value = self.details
        if not details_value:
            return {}
        try:
            return json.loads(str(details_value))
        except:
            return {}

class OperationLog(Base):
    """Operation log table"""
    __tablename__ = 'operation_logs'
    
    id = Column(Integer, primary_key=True)
    level = Column(String(16), default='INFO')
    operation = Column(String(64), nullable=False)
    message = Column(Text, nullable=False)
    details = Column(Text, nullable=True)  # JSON string
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<OperationLog(id={self.id}, level='{self.level}', operation='{self.operation}', timestamp='{self.timestamp}')>"

class Strategy(Base):
    """Strategy table"""
    __tablename__ = 'strategies'
    
    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=True)  # Stratejinin adı
    type = Column(String(32), nullable=False)  # pump_it, gradual_sell, dump_it, dynamic_trading, etc.
    wallet_address = Column(String(256), nullable=True)  # Stratejiyi çalıştıran cüzdan
    wallet_id = Column(String(64), ForeignKey('wallets.id'), nullable=True)  # İlişkili cüzdan ID'si
    token_address = Column(String(256), ForeignKey('tokens.address'), nullable=True)  # İlişkili token adresi (boş olabilir)
    parameters = Column(Text, nullable=False)  # JSON string
    status = Column(String(32), default='created')  # created, running, completed, failed
    results = Column(Text, nullable=True)  # JSON string
    is_test = Column(Boolean, default=False)  # Test stratejisi mi?
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    wallet = relationship("Wallet", foreign_keys=[wallet_id])
    token = relationship("Token", primaryjoin="Strategy.token_address == Token.address", viewonly=True)
    
    def __repr__(self):
        return f"<Strategy(id='{self.id}', type='{self.type}', status='{self.status}')>"

# Alias for compatibility with enhanced_pump_dump_strategies.py
TradingStrategy = Strategy

class LiquidityPosition(Base):
    """Liquidity position table"""
    __tablename__ = 'liquidity_positions'
    __table_args__ = {'extend_existing': True}
    
    id = Column(String(64), primary_key=True)
    wallet_id = Column(String(64), ForeignKey('wallets.id'), nullable=False)
    pair_address = Column(String(256), nullable=False)
    token_a_address = Column(String(256), nullable=False)
    token_b_address = Column(String(256), nullable=False)
    token_a_amount = Column(Float, nullable=False)
    token_b_amount = Column(Float, nullable=False)
    pool_share = Column(Float, nullable=True)
    value_usd = Column(Float, nullable=True)
    dex_id = Column(String(32), default='raydium')
    network = Column(String(32), default='devnet')
    status = Column(String(32), default='active')  # active, removed
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    wallet = relationship("Wallet", back_populates="liquidity_positions")
    
    def __repr__(self):
        return f"<LiquidityPosition(id='{self.id}', wallet='{self.wallet_id}', pair='{self.pair_address[:8]}...', status='{self.status}')>"

# Model for storing wallet keys as serialized objects
class WalletData:
    """In-memory wallet data structure"""
    
    def __init__(self, id, public_key, private_key=None, name=None, balance=0.0, network='devnet'):
        self.id = id
        self.public_key = public_key
        self.private_key = private_key
        self.name = name or f"Wallet-{id[:8]}"
        self.balance = balance
        self.network = network
    
    def to_dict(self, include_private=False):
        """Convert to dictionary (with option to include private key)"""
        result = {
            "id": self.id,
            "public_key": self.public_key,
            "name": self.name,
            "balance": self.balance,
            "network": self.network
        }
        
        if include_private and self.private_key:
            result["private_key"] = self.private_key
            
        return result

class PoolMonitoring(Base):
    """Real-time pool monitoring"""
    __tablename__ = 'pool_monitoring'
    
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    pool_address = Column(String(256), nullable=False, unique=True)
    token_address = Column(String(256), nullable=False)
    token_name = Column(String(128), nullable=True)
    token_symbol = Column(String(32), nullable=True)
    liquidity_sol = Column(Float, nullable=True)
    volume_24h = Column(Float, nullable=True)
    mint_authority_revoked = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SnipeList(Base):
    """Snipe list for targeted tokens"""
    __tablename__ = 'snipe_list'
    
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    token_address = Column(String(256), nullable=False, unique=True)
    token_name = Column(String(128), nullable=True)
    token_symbol = Column(String(32), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class TradingConfig(Base):
    """Advanced trading configuration"""
    __tablename__ = 'trading_config'
    
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(64), nullable=False)
    stop_loss_percentage = Column(Float, default=50.0)
    take_profit_percentage = Column(Float, default=300.0)
    min_pool_size_sol = Column(Float, default=2.0)
    auto_sell_enabled = Column(Boolean, default=True)
    auto_sell_delay_seconds = Column(Integer, default=20)
    max_retries = Column(Integer, default=5)
    retry_delay_ms = Column(Integer, default=1000)
    snipe_list_enabled = Column(Boolean, default=False)
    real_time_monitoring_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
