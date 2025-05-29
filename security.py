from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import secrets
import re
import ipaddress
import logging
import pyotp
import qrcode
from io import BytesIO
import json
from typing import Dict, Any, List, Optional, Union, Tuple
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class SecurityManager:
    """
    Security management class for the application.
    """
    
    def __init__(self, encryption_key: Optional[str] = None):
        """
        Initialize security manager
        
        Args:
            encryption_key: Encryption key (generated if None)
        """
        # Get encryption key from environment or generate one
        if not encryption_key:
            encryption_key = os.environ.get('ENCRYPTION_KEY', None)
            
            if not encryption_key:
                # Generate random key
                encryption_key = self._generate_encryption_key()
                logger.warning("No encryption key provided. Generated a random key.")
        
        self.encryption_key = encryption_key
        self._cipher = self._create_cipher(encryption_key)
        
        # IP whitelists/blacklists
        self.ip_whitelist = []
        self.ip_blacklist = []
        
        # API rate limiting
        self.rate_limits = {}
        
        # CSRF tokens
        self.csrf_tokens = {}
        
        # Login attempts tracking
        self.failed_login_attempts = {}
        
        # Transaction limits
        self.transaction_limits = {
            'default': {
                'daily_limit': 1000.0,  # SOL
                'per_transaction': 100.0,  # SOL
                'require_2fa': True,     # Require 2FA for transactions
                'require_approval': 50.0  # Transactions over this amount need approval
            }
        }
        
        # Active sessions tracking
        self.active_sessions = {}
    
    def _generate_encryption_key(self) -> str:
        """Generate a random encryption key"""
        return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
    
    def _create_cipher(self, key_string: str) -> Fernet:
        """
        Create a Fernet cipher from key string
        
        Args:
            key_string: Encryption key string
            
        Returns:
            Fernet cipher object
        """
        # Convert string to 32 byte fixed length
        key_bytes = self._string_to_key(key_string)
        return Fernet(base64.urlsafe_b64encode(key_bytes))
    
    def _string_to_key(self, key_string: str) -> bytes:
        """
        Convert string to 32-byte key
        
        Args:
            key_string: Key string
            
        Returns:
            32-byte key
        """
        # Use fixed salt value
        salt = b'washbot_secure_salt_value'
        
        # Derive key with PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        
        return kdf.derive(key_string.encode())
    
    def encrypt_data(self, data: Union[str, bytes]) -> str:
        """
        Encrypt data
        
        Args:
            data: Data to encrypt (string or bytes)
            
        Returns:
            Base64 encoded encrypted data
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        encrypted_data = self._cipher.encrypt(data)
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """
        Decrypt data
        
        Args:
            encrypted_data: Base64 encoded encrypted data
            
        Returns:
            Decrypted data (string)
        """
        encrypted_bytes = base64.b64decode(encrypted_data)
        decrypted_data = self._cipher.decrypt(encrypted_bytes)
        return decrypted_data.decode('utf-8')
    
    def hash_password(self, password: str) -> str:
        """
        Securely hash password (using bcrypt)
        
        Args:
            password: Raw password
            
        Returns:
            Hashed password
        """
        import bcrypt
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify password against hash
        
        Args:
            password: Password to check
            hashed_password: Hashed password
            
        Returns:
            Match status (True/False)
        """
        import bcrypt
        return bcrypt.checkpw(
            password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    
    def generate_csrf_token(self, session_id: str) -> str:
        """
        Generate CSRF token
        
        Args:
            session_id: Session ID
            
        Returns:
            CSRF token
        """
        token = secrets.token_hex(32)
        expiry = datetime.now() + timedelta(hours=24)
        
        self.csrf_tokens[session_id] = {
            'token': token,
            'expires': expiry
        }
        
        return token
    
    def verify_csrf_token(self, session_id: str, token: str) -> bool:
        """
        Verify CSRF token
        
        Args:
            session_id: Session ID
            token: Token to verify
            
        Returns:
            Verification result (True/False)
        """
        if session_id not in self.csrf_tokens:
            return False
            
        stored_token = self.csrf_tokens[session_id]
        
        # Check if expired
        if datetime.now() > stored_token['expires']:
            del self.csrf_tokens[session_id]
            return False
            
        # Check token match
        return stored_token['token'] == token
    
    def is_ip_allowed(self, ip_address: str) -> bool:
        """
        Check if IP address is allowed
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Allow status (True/False)
        """
        try:
            # Validate IP format
            ipaddress.ip_address(ip_address)
            
            # Check blacklist
            if self.ip_blacklist and any(self._ip_matches(ip_address, pattern) for pattern in self.ip_blacklist):
                return False
                
            # Allow all if whitelist is empty
            if not self.ip_whitelist:
                return True
                
            # Check whitelist
            return any(self._ip_matches(ip_address, pattern) for pattern in self.ip_whitelist)
            
        except ValueError:
            # Invalid IP address
            logger.warning(f"Invalid IP address format: {ip_address}")
            return False
    
    def _ip_matches(self, ip_address: str, pattern: str) -> bool:
        """
        Check if IP matches pattern
        
        Args:
            ip_address: IP address to check
            pattern: IP pattern (CIDR notation supported, e.g. "192.168.1.0/24")
            
        Returns:
            Match status (True/False)
        """
        try:
            # CIDR notation?
            if '/' in pattern:
                network = ipaddress.ip_network(pattern, strict=False)
                return ipaddress.ip_address(ip_address) in network
            else:
                # Exact match
                return ip_address == pattern
                
        except ValueError:
            logger.warning(f"Invalid IP pattern: {pattern}")
            return False
    
    def check_rate_limit(self, key: str, limit: int, period: int = 60) -> bool:
        """
        Check rate limit
        
        Args:
            key: Rate limit key (e.g. "ip:192.168.1.1" or "user:123")
            limit: Maximum allowed requests
            period: Period in seconds
            
        Returns:
            Allow status (True: limit not exceeded, False: limit exceeded)
        """
        now = datetime.now()
        
        # Create rate limit data if not exists
        if key not in self.rate_limits:
            self.rate_limits[key] = {
                'count': 0,
                'reset_at': now + timedelta(seconds=period)
            }
        
        # Reset if period expired
        if now > self.rate_limits[key]['reset_at']:
            self.rate_limits[key] = {
                'count': 0,
                'reset_at': now + timedelta(seconds=period)
            }
        
        # Increment request count
        self.rate_limits[key]['count'] += 1
        
        # Check if limit exceeded
        return self.rate_limits[key]['count'] <= limit
    
    # 2FA functions
    def generate_2fa_secret(self) -> str:
        """
        Generate a new 2FA secret key
        
        Returns:
            Secret key (base32 encoded)
        """
        return pyotp.random_base32()
    
    def generate_2fa_qr_code(self, username: str, secret: str) -> BytesIO:
        """
        Generate QR code for 2FA setup
        
        Args:
            username: User's username
            secret: 2FA secret key
            
        Returns:
            QR code image as BytesIO
        """
        # Create TOTP URI
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(username, issuer_name="WashBot")
        
        # Generate QR code directly using qrcode.make
        img = qrcode.make(uri)
        
        # Save to BytesIO
        buffer = BytesIO()
        img.save(buffer)
        buffer.seek(0)
        
        return buffer
    
    def verify_2fa_code(self, secret: str, code: str) -> bool:
        """
        Verify 2FA code
        
        Args:
            secret: 2FA secret key
            code: 2FA code to verify
            
        Returns:
            Verification result (True/False)
        """
        if not secret or not code:
            return False
            
        # Kod sadece sayılardan oluşmalı
        if not code.isdigit():
            return False
            
        # Biraz daha geniş zaman aralığı kullan (önce ve sonra 1 periyot)
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)
    
    # Account security functions
    def track_login_attempt(self, user_id: str, success: bool, ip_address: str) -> Tuple[bool, int]:
        """
        Track login attempts for account security
        
        Args:
            user_id: User ID
            success: Login success status
            ip_address: Client IP address
            
        Returns:
            Tuple of (account_locked, remaining_attempts)
        """
        now = datetime.now()
        key = f"login:{user_id}"
        
        # Initialize tracking for user if not exists
        if key not in self.failed_login_attempts:
            self.failed_login_attempts[key] = {
                'attempts': [],
                'locked_until': None
            }
        
        # Check if account is locked
        if self.failed_login_attempts[key]['locked_until'] and now < self.failed_login_attempts[key]['locked_until']:
            # Account is locked
            return (True, 0)
        else:
            # Reset lock if expired
            self.failed_login_attempts[key]['locked_until'] = None
        
        # If successful login, reset failed attempts
        if success:
            self.failed_login_attempts[key]['attempts'] = []
            return (False, 5)
        
        # Add failed attempt
        self.failed_login_attempts[key]['attempts'].append({
            'timestamp': now,
            'ip_address': ip_address
        })
        
        # Remove attempts older than 15 minutes
        self.failed_login_attempts[key]['attempts'] = [
            a for a in self.failed_login_attempts[key]['attempts']
            if (now - a['timestamp']).seconds < 900
        ]
        
        # Check failed attempt count
        attempt_count = len(self.failed_login_attempts[key]['attempts'])
        remaining_attempts = max(5 - attempt_count, 0)
        
        # Lock account if too many failed attempts
        if attempt_count >= 5:
            # Lock for 30 minutes
            self.failed_login_attempts[key]['locked_until'] = now + timedelta(minutes=30)
            return (True, 0)
        
        return (False, remaining_attempts)
    
    def track_session(self, session_id: str, user_id: str, ip_address: str) -> None:
        """
        Track user session
        
        Args:
            session_id: Session ID
            user_id: User ID
            ip_address: Client IP address
        """
        now = datetime.now()
        
        # Add to active sessions
        self.active_sessions[session_id] = {
            'user_id': user_id,
            'ip_address': ip_address,
            'created_at': now,
            'last_active': now
        }
    
    def update_session_activity(self, session_id: str) -> None:
        """
        Update session last activity time
        
        Args:
            session_id: Session ID
        """
        if session_id in self.active_sessions:
            self.active_sessions[session_id]['last_active'] = datetime.now()
    
    def end_session(self, session_id: str) -> None:
        """
        End user session
        
        Args:
            session_id: Session ID
        """
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
    
    def check_suspicious_activity(self, session_id: str, ip_address: str) -> bool:
        """
        Check for suspicious activity on session
        
        Args:
            session_id: Session ID
            ip_address: Current IP address
            
        Returns:
            Suspicious activity detected (True/False)
        """
        if session_id not in self.active_sessions:
            return True
        
        # Check IP address change
        if self.active_sessions[session_id]['ip_address'] != ip_address:
            return True
        
        # Check session age (24 hours)
        now = datetime.now()
        if (now - self.active_sessions[session_id]['created_at']).seconds > 86400:
            return True
        
        # Check inactivity (1 hour)
        if (now - self.active_sessions[session_id]['last_active']).seconds > 3600:
            return True
        
        return False
    
    # Transaction security
    def check_transaction_limits(self, user_id: str, amount: float) -> Dict[str, Any]:
        """
        Check transaction limits
        
        Args:
            user_id: User ID
            amount: Transaction amount (in SOL)
            
        Returns:
            Transaction check result
        """
        # Use user-specific limits if available, otherwise use default
        limits_key = user_id if user_id in self.transaction_limits else 'default'
        limits = self.transaction_limits[limits_key]
        
        # Check if transaction exceeds per-transaction limit
        exceeds_transaction_limit = amount > limits['per_transaction']
        
        # Check if transaction requires 2FA
        requires_2fa = limits['require_2fa']
        
        # Check if transaction requires approval
        requires_approval = amount > limits['require_approval']
        
        # Return result
        return {
            'allowed': not exceeds_transaction_limit,
            'requires_2fa': requires_2fa,
            'requires_approval': requires_approval,
            'reason': 'Transaction exceeds limit' if exceeds_transaction_limit else None
        }
    
    def set_user_transaction_limits(self, user_id: str, limits: Dict[str, Any]) -> None:
        """
        Set transaction limits for a user
        
        Args:
            user_id: User ID
            limits: Transaction limits
        """
        self.transaction_limits[user_id] = limits
