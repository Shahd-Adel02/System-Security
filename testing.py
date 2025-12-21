"""
================================================================================
SECURE LOGIN SYSTEM - COMPREHENSIVE SECURITY IMPLEMENTATION
================================================================================
This module implements a robust, production-ready secure login system with
multiple security layers including password hashing, account lockout protection,
input validation, comprehensive logging, and session management.
Version: 2.0
Date: 2025
================================================================================
"""

import re
import hashlib
import logging
import os
import json
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, List
from collections import defaultdict


# ============================================================================
# MODULE 1: CONFIGURATION MANAGEMENT
# ============================================================================
class SecurityConfig:
    """
    Centralized configuration management for security parameters.
    This class stores all configurable security settings in one place,
    making it easy to adjust security policies without modifying core logic.
    """
    
    # Password requirements
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_NUMBERS = True
    REQUIRE_SPECIAL_CHARS = True
    ALLOWED_SPECIAL_CHARS = "!#$%&?@*+-_=[]{}|;:,.<>"
    
    # Username requirements
    MIN_USERNAME_LENGTH = 3
    MAX_USERNAME_LENGTH = 20
    USERNAME_ALLOWED_CHARS = r'^[a-zA-Z0-9_]+$'
    
    # Account lockout settings
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION_SECONDS = 300  # 5 minutes
    RESET_ATTEMPTS_ON_SUCCESS = True
    
    # Session management
    SESSION_TIMEOUT_SECONDS = 3600  # 1 hour
    MAX_CONCURRENT_SESSIONS = 3
    
    # Logging configuration
    LOG_FILE = "logindata.log"
    LOG_LEVEL = logging.INFO
    LOG_FORMAT = "LOG | %(levelname)s | %(asctime)s | %(message)s"
    ENABLE_DETAILED_LOGGING = True
    
    # Password hashing
    HASH_ALGORITHM = "sha256"
    USE_SALT = True  # For future enhancement with salt
    
    @classmethod
    def get_password_requirements(cls) -> Dict[str, any]:
        """Returns a dictionary of all password requirements for display."""
        return {
            "min_length": cls.MIN_PASSWORD_LENGTH,
            "max_length": cls.MAX_PASSWORD_LENGTH,
            "require_uppercase": cls.REQUIRE_UPPERCASE,
            "require_lowercase": cls.REQUIRE_LOWERCASE,
            "require_numbers": cls.REQUIRE_NUMBERS,
            "require_special_chars": cls.REQUIRE_SPECIAL_CHARS,
            "allowed_special_chars": cls.ALLOWED_SPECIAL_CHARS
        }


# ============================================================================
# MODULE 2: LOGGING AND ERROR HANDLING
# ============================================================================
class SecurityLogger:
    """
    Comprehensive logging system for security events.
    Logs all authentication attempts, user creation, password changes,
    and security violations for audit and security analysis purposes.
    """
    
    _logger_initialized = False
    
    @staticmethod
    def initialize_logger() -> bool:
        """
        Initializes the logging system with proper configuration.
        
        Returns:
            bool: True if initialization successful, False otherwise
        """
        try:
            if not SecurityLogger._logger_initialized:
                # Create logs directory if it doesn't exist
                log_dir = os.path.dirname(SecurityConfig.LOG_FILE) or "."
                if log_dir != "." and not os.path.exists(log_dir):
                    os.makedirs(log_dir, exist_ok=True)
                
                # Configure logging with file handler
                logging.basicConfig(
                    filename=SecurityConfig.LOG_FILE,
                    level=SecurityConfig.LOG_LEVEL,
                    format=SecurityConfig.LOG_FORMAT,
                    filemode='a',  # Append mode to preserve log history
                    encoding='utf-8'
                )
                
                # Also add console handler for immediate feedback
                console_handler = logging.StreamHandler()
                console_handler.setLevel(logging.WARNING)  # Only warnings/errors to console
                console_formatter = logging.Formatter(SecurityConfig.LOG_FORMAT)
                console_handler.setFormatter(console_formatter)
                logging.getLogger().addHandler(console_handler)
                
                SecurityLogger._logger_initialized = True
                logging.info("=" * 80)
                logging.info("Security Logger Initialized Successfully")
                logging.info("=" * 80)
                return True
        except Exception as e:
            print(f"😵‍💫 Critical Error: Failed to initialize logger - {e}")
            return False
        return True
    
    @staticmethod
    def log_event(event_type: str, message: str, username: Optional[str] = None, 
                  severity: str = "INFO") -> None:
        """
        Logs a security event with detailed information.
        
        Args:
            event_type: Type of event (e.g., "LOGIN_ATTEMPT", "USER_CREATED")
            message: Detailed message about the event
            username: Username associated with the event (if applicable)
            severity: Log level (INFO, WARNING, ERROR, CRITICAL)
        """
        if not SecurityLogger._logger_initialized:
            SecurityLogger.initialize_logger()
        
        log_message = f"[{event_type}]"
        if username:
            log_message += f" User: {username}"
        log_message += f" | {message}"
        
        if severity == "INFO":
            logging.info(log_message)
        elif severity == "WARNING":
            logging.warning(log_message)
        elif severity == "ERROR":
            logging.error(log_message)
        elif severity == "CRITICAL":
            logging.critical(log_message)
    
    @staticmethod
    def log_login_attempt(username: str, success: bool, reason: str = "") -> None:
        """Logs a login attempt with success/failure status."""
        status = "SUCCESS" if success else "FAILED"
        message = f"Login attempt {status}"
        if reason:
            message += f" - {reason}"
        severity = "INFO" if success else "WARNING"
        SecurityLogger.log_event("LOGIN_ATTEMPT", message, username, severity)
    
    @staticmethod
    def log_user_creation(username: str, success: bool) -> None:
        """Logs user account creation."""
        status = "SUCCESS" if success else "FAILED"
        SecurityLogger.log_event("USER_CREATION", f"User creation {status}", username)
    
    @staticmethod
    def log_password_change(username: str, success: bool) -> None:
        """Logs password change attempts."""
        status = "SUCCESS" if success else "FAILED"
        SecurityLogger.log_event("PASSWORD_CHANGE", f"Password change {status}", username)
    
    @staticmethod
    def log_security_violation(violation_type: str, username: Optional[str] = None, 
                               details: str = "") -> None:
        """Logs security violations and suspicious activities."""
        message = f"Security violation: {violation_type}"
        if details:
            message += f" - {details}"
        SecurityLogger.log_event("SECURITY_VIOLATION", message, username, "WARNING")


# Initialize logger at module level
SecurityLogger.initialize_logger()


# ============================================================================
# MODULE 3: INPUT VALIDATION AND SANITIZATION
# ============================================================================
class InputValidator:
    """
    Comprehensive input validation and sanitization module.
    Validates usernames, passwords, and other user inputs according to
    security policies defined in SecurityConfig.
    """
    
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        """
        Validates username according to security requirements.
        
        Args:
            username: The username to validate
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        if not username:
            return False, "Username cannot be empty"
        
        username = username.strip()
        
        # Check length
        if len(username) < SecurityConfig.MIN_USERNAME_LENGTH:
            return False, f"Username must be at least {SecurityConfig.MIN_USERNAME_LENGTH} characters"
        
        if len(username) > SecurityConfig.MAX_USERNAME_LENGTH:
            return False, f"Username must be no more than {SecurityConfig.MAX_USERNAME_LENGTH} characters"
        
        # Check allowed characters (alphanumeric and underscore only)
        if not re.match(SecurityConfig.USERNAME_ALLOWED_CHARS, username):
            return False, "Username can only contain letters, numbers, and underscores"
        
        # Check if starts with letter
        if not username[0].isalpha():
            return False, "Username must start with a letter"
        
        # Check for reserved words (basic check)
        reserved_words = ["admin", "root", "system", "guest", "null", "test"]
        if username.lower() in reserved_words:
            return False, "Username is reserved and cannot be used"
        
        return True, ""
    
    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
        """
        Validates password strength according to security requirements.
        Returns detailed feedback about what requirements are not met.
        
        Args:
            password: The password to validate
            
        Returns:
            Tuple[bool, List[str]]: (is_valid, list_of_errors)
        """
        errors = []
        
        if not password:
            return False, ["Password cannot be empty"]
        
        # Check length
        if len(password) < SecurityConfig.MIN_PASSWORD_LENGTH:
            errors.append(f"Password must be at least {SecurityConfig.MIN_PASSWORD_LENGTH} characters long")
        
        if len(password) > SecurityConfig.MAX_PASSWORD_LENGTH:
            errors.append(f"Password must be no more than {SecurityConfig.MAX_PASSWORD_LENGTH} characters")
        
        # Check for uppercase letters
        if SecurityConfig.REQUIRE_UPPERCASE:
            if not re.search(r"[A-Z]", password):
                errors.append("Password must contain at least one uppercase letter")
        
        # Check for lowercase letters
        if SecurityConfig.REQUIRE_LOWERCASE:
            if not re.search(r"[a-z]", password):
                errors.append("Password must contain at least one lowercase letter")
        
        # Check for numbers
        if SecurityConfig.REQUIRE_NUMBERS:
            if not re.search(r"[0-9]", password):
                errors.append("Password must contain at least one number")
        
        # Check for special characters
        if SecurityConfig.REQUIRE_SPECIAL_CHARS:
            special_char_pattern = "[" + re.escape(SecurityConfig.ALLOWED_SPECIAL_CHARS) + "]"
            if not re.search(special_char_pattern, password):
                errors.append(f"Password must contain at least one special character from: {SecurityConfig.ALLOWED_SPECIAL_CHARS}")
        
        # Check for common weak passwords
        common_passwords = ["password", "12345678", "qwerty", "abc123", "password123"]
        if password.lower() in common_passwords:
            errors.append("Password is too common and easily guessable")
        
        # Check for repeated characters (e.g., "aaaaaaa")
        if re.search(r'(.)\1{3,}', password):
            errors.append("Password contains too many repeated characters")
        
        # Check for sequential characters (e.g., "1234", "abcd")
        sequences = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
        password_lower = password.lower()
        for seq in sequences:
            for i in range(len(seq) - 3):
                if seq[i:i+4] in password_lower:
                    errors.append("Password contains easily guessable sequences")
                    break
        
        is_valid = len(errors) == 0
        return is_valid, errors
    
    @staticmethod
    def sanitize_input(user_input: str, max_length: int = 1000) -> str:
        """
        Sanitizes user input to prevent injection attacks.
        
        Args:
            user_input: The input to sanitize
            max_length: Maximum allowed length
            
        Returns:
            str: Sanitized input
        """
        if not user_input:
            return ""
        
        # Remove leading/trailing whitespace
        sanitized = user_input.strip()
        
        # Truncate if too long
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
            SecurityLogger.log_security_violation("INPUT_TOO_LONG", details=f"Input truncated from {len(user_input)} to {max_length}")
        
        # Remove null bytes and control characters
        sanitized = ''.join(char for char in sanitized if ord(char) >= 32 or char in '\n\r\t')
        
        return sanitized


# ============================================================================
# MODULE 4: PASSWORD HASHING AND SECURITY
# ============================================================================
class PasswordManager:
    """
    Handles password hashing and verification using secure algorithms.
    Uses SHA-256 hashing (can be upgraded to bcrypt/argon2 in production).
    """
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hashes a password using SHA-256 algorithm.
        
        Args:
            password: Plain text password to hash
            
        Returns:
            str: Hexadecimal hash of the password
        """
        try:
            if not password:
                raise ValueError("Password cannot be empty")
            
            # Encode password to bytes
            password_bytes = password.encode('utf-8')
            
            # Create hash using SHA-256
            hash_object = hashlib.sha256(password_bytes)
            password_hash = hash_object.hexdigest()
            
            return password_hash
        except Exception as e:
            SecurityLogger.log_event("PASSWORD_HASH_ERROR", f"Failed to hash password: {e}", severity="ERROR")
            raise
    
    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        """
        Verifies a password against a stored hash.
        
        Args:
            password: Plain text password to verify
            stored_hash: Stored hash to compare against
            
        Returns:
            bool: True if password matches, False otherwise
        """
        try:
            computed_hash = PasswordManager.hash_password(password)
            return computed_hash == stored_hash
        except Exception as e:
            SecurityLogger.log_event("PASSWORD_VERIFY_ERROR", f"Failed to verify password: {e}", severity="ERROR")
            return False
    
    @staticmethod
    def generate_password_strength_score(password: str) -> int:
        """
        Calculates a password strength score (0-100).
        
        Args:
            password: Password to score
            
        Returns:
            int: Strength score from 0 (weak) to 100 (strong)
        """
        score = 0
        
        # Length contribution (max 30 points)
        length_score = min(30, len(password) * 2)
        score += length_score
        
        # Character variety (max 40 points)
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[!#$%&?@*+-_=]', password))
        
        variety_count = sum([has_upper, has_lower, has_digit, has_special])
        score += variety_count * 10
        
        # Complexity bonus (max 30 points)
        if len(password) >= 12:
            score += 10
        if len(password) >= 16:
            score += 10
        if len(set(password)) / len(password) > 0.7:  # High character diversity
            score += 10
        
        return min(100, score)


# ============================================================================
# MODULE 5: SESSION MANAGEMENT
# ============================================================================
class SessionManager:
    """
    Manages user sessions to track active logins and prevent session hijacking.
    Tracks session creation time, last activity, and enforces session timeouts.
    """
    
    def __init__(self):
        """Initializes the session manager."""
        self.sessions: Dict[str, Dict] = {}  # username -> session info
        self.session_tokens: Dict[str, str] = {}  # token -> username
    
    def create_session(self, username: str) -> str:
        """
        Creates a new session for a user.
        
        Args:
            username: Username to create session for
            
        Returns:
            str: Session token
        """
        # Check for maximum concurrent sessions
        user_sessions = [s for s in self.sessions.values() if s.get('username') == username]
        if len(user_sessions) >= SecurityConfig.MAX_CONCURRENT_SESSIONS:
            # Remove oldest session
            oldest = min(user_sessions, key=lambda x: x['created_at'])
            self.end_session(oldest['token'])
        
        # Generate session token
        token = self._generate_token(username)
        
        # Create session
        session = {
            'username': username,
            'token': token,
            'created_at': datetime.now(),
            'last_activity': datetime.now(),
            'active': True
        }
        
        self.sessions[username] = session
        self.session_tokens[token] = username
        
        SecurityLogger.log_event("SESSION_CREATED", f"New session created", username)
        return token
    
    def _generate_token(self, username: str) -> str:
        """Generates a unique session token."""
        timestamp = str(time.time())
        data = f"{username}{timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]
    
    def validate_session(self, token: str) -> Tuple[bool, Optional[str]]:
        """
        Validates a session token and checks if session is still active.
        
        Args:
            token: Session token to validate
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, username or None)
        """
        if token not in self.session_tokens:
            return False, None
        
        username = self.session_tokens[token]
        if username not in self.sessions:
            return False, None
        
        session = self.sessions[username]
        
        # Check if session is active
        if not session.get('active', False):
            return False, None
        
        # Check session timeout
        time_since_activity = datetime.now() - session['last_activity']
        if time_since_activity.total_seconds() > SecurityConfig.SESSION_TIMEOUT_SECONDS:
            self.end_session(token)
            SecurityLogger.log_event("SESSION_EXPIRED", "Session expired due to inactivity", username)
            return False, None
        
        # Update last activity
        session['last_activity'] = datetime.now()
        return True, username
    
    def end_session(self, token: str) -> bool:
        """
        Ends a session.
        
        Args:
            token: Session token to end
            
        Returns:
            bool: True if session was ended, False if not found
        """
        if token not in self.session_tokens:
            return False
        
        username = self.session_tokens[token]
        if username in self.sessions:
            self.sessions[username]['active'] = False
            SecurityLogger.log_event("SESSION_ENDED", "Session ended", username)
        
        del self.session_tokens[token]
        return True
    
    def cleanup_expired_sessions(self) -> int:
        """
        Removes all expired sessions.
        
        Returns:
            int: Number of sessions cleaned up
        """
        count = 0
        now = datetime.now()
        
        for username, session in list(self.sessions.items()):
            if not session.get('active', False):
                continue
            
            time_since_activity = now - session['last_activity']
            if time_since_activity.total_seconds() > SecurityConfig.SESSION_TIMEOUT_SECONDS:
                self.end_session(session['token'])
                count += 1
        
        return count


# ============================================================================
# MODULE 6: ACCOUNT LOCKOUT MANAGEMENT
# ============================================================================
class LockoutManager:
    """
    Manages account lockout functionality to prevent brute force attacks.
    Tracks failed login attempts per user and locks accounts after threshold.
    """
    
    def __init__(self):
        """Initializes the lockout manager."""
        self.failed_attempts: Dict[str, int] = defaultdict(int)
        self.lockout_times: Dict[str, datetime] = {}
        self.global_failed_attempts = 0
    
    def record_failed_attempt(self, username: str) -> None:
        """
        Records a failed login attempt for a user.
        
        Args:
            username: Username that failed to login
        """
        self.failed_attempts[username] += 1
        self.global_failed_attempts += 1
        
        SecurityLogger.log_security_violation(
            "FAILED_LOGIN_ATTEMPT",
            username,
            f"Attempt {self.failed_attempts[username]} of {SecurityConfig.MAX_FAILED_ATTEMPTS}"
        )
        
        # Lock account if threshold reached
        if self.failed_attempts[username] >= SecurityConfig.MAX_FAILED_ATTEMPTS:
            self.lock_account(username)
    
    def record_successful_login(self, username: str) -> None:
        """
        Records a successful login and resets failed attempts if configured.
        
        Args:
            username: Username that successfully logged in
        """
        if SecurityConfig.RESET_ATTEMPTS_ON_SUCCESS:
            self.reset_attempts(username)
    
    def is_locked(self, username: str) -> Tuple[bool, Optional[str]]:
        """
        Checks if an account is currently locked.
        
        Args:
            username: Username to check
            
        Returns:
            Tuple[bool, Optional[str]]: (is_locked, reason_message)
        """
        # Check per-user lockout
        if username in self.lockout_times:
            lockout_time = self.lockout_times[username]
            time_remaining = (lockout_time + timedelta(seconds=SecurityConfig.LOCKOUT_DURATION_SECONDS)) - datetime.now()
            
            if time_remaining.total_seconds() > 0:
                minutes = int(time_remaining.total_seconds() / 60)
                seconds = int(time_remaining.total_seconds() % 60)
                return True, f"Account locked. Try again in {minutes}m {seconds}s"
            else:
                # Lockout expired, remove it
                del self.lockout_times[username]
                self.reset_attempts(username)
        
        # Check global lockout
        if self.global_failed_attempts >= SecurityConfig.MAX_FAILED_ATTEMPTS * 10:
            return True, "System temporarily locked due to excessive failed attempts"
        
        return False, None
    
    def lock_account(self, username: str) -> None:
        """
        Locks an account for the configured lockout duration.
        
        Args:
            username: Username to lock
        """
        self.lockout_times[username] = datetime.now()
        SecurityLogger.log_security_violation(
            "ACCOUNT_LOCKED",
            username,
            f"Account locked after {self.failed_attempts[username]} failed attempts"
        )
    
    def reset_attempts(self, username: str) -> None:
        """
        Resets failed attempt counter for a user.
        
        Args:
            username: Username to reset attempts for
        """
        if username in self.failed_attempts:
            del self.failed_attempts[username]
    
    def get_attempts_remaining(self, username: str) -> int:
        """
        Gets the number of attempts remaining before lockout.
        
        Args:
            username: Username to check
            
        Returns:
            int: Number of attempts remaining
        """
        attempts = self.failed_attempts.get(username, 0)
        return max(0, SecurityConfig.MAX_FAILED_ATTEMPTS - attempts)


# ============================================================================
# MODULE 7: MAIN LOGIN SYSTEM
# ============================================================================
class SecureLoginSystem:
    """
    Main secure login system that integrates all security modules.
    Provides user registration, authentication, password management,
    and comprehensive security features.
    """
    
    def __init__(self):
        """Initializes the secure login system."""
        self.users: Dict[str, Dict] = {}  # username -> {password_hash, created_at, last_login}
        self.session_manager = SessionManager()
        self.lockout_manager = LockoutManager()
        SecurityLogger.log_event("SYSTEM_INIT", "Secure Login System initialized")
    
    def create_user(self, username: Optional[str] = None, password: Optional[str] = None) -> Tuple[bool, str]:
        """
        Creates a new user account with validation and security checks.
        
        Args:
            username: Optional username (if None, prompts user)
            password: Optional password (if None, prompts user)
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        try:
            # Get username
            if username is None:
                print("\033[0m🫡 Enter username:\033[0m")
                username_input = input("\n> ").strip()
            else:
                username_input = username.strip()
            
            username_input = InputValidator.sanitize_input(username_input)
            
            # Validate username
            is_valid, error_msg = InputValidator.validate_username(username_input)
            if not is_valid:
                print(f"\033[91m❌ Invalid username: {error_msg}\033[0m")
                SecurityLogger.log_user_creation(username_input, False)
                return False, error_msg
            
            # Check if username already exists
            if username_input in self.users:
                print(f"\033[91m❌ Username '{username_input}' already exists\033[0m")
                SecurityLogger.log_user_creation(username_input, False)
                return False, "Username already exists"
            
            # Get password
            if password is None:
                print("\n🤐 Enter STRONG password:")
                password_input = input("\n> ").strip()
            else:
                password_input = password.strip()
            
            password_input = InputValidator.sanitize_input(password_input)
            
            # Validate password
            is_valid, errors = InputValidator.validate_password_strength(password_input)
            if not is_valid:
                print("\n\033[91m😓 Weak password detected!\033[0m")
                print("\033[93m👻 Please ensure your password:\033[0m")
                for error in errors:
                    print(f"   • {error}")
                print(f"\n\033[0m Try again:\033[0m")
                SecurityLogger.log_user_creation(username_input, False)
                return False, "; ".join(errors)
            
            # Calculate password strength
            strength_score = PasswordManager.generate_password_strength_score(password_input)
            strength_level = "Weak" if strength_score < 50 else "Medium" if strength_score < 75 else "Strong"
            print(f"\033[94m📊 Password strength: {strength_level} ({strength_score}/100)\033[0m")
            
            # Hash and store password
            password_hash = PasswordManager.hash_password(password_input)
            self.users[username_input] = {
                'password_hash': password_hash,
                'created_at': datetime.now(),
                'last_login': None,
                'login_count': 0
            }
            
            print(f"\n\033[92m✅ User '{username_input}' created successfully! 🎉\033[0m")
            SecurityLogger.log_user_creation(username_input, True)
            return True, "User created successfully"
            
        except KeyboardInterrupt:
            print("\n\n⚠️  User creation cancelled")
            return False, "Cancelled by user"
        except Exception as e:
            error_msg = f"Could not create user: {e}"
            print(f"\033[91m❌ {error_msg}\033[0m")
            SecurityLogger.log_event("USER_CREATION_ERROR", error_msg, severity="ERROR")
            return False, error_msg
    
    def login(self, username: Optional[str] = None, password: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Authenticates a user with comprehensive security checks.
        
        Args:
            username: Optional username (if None, prompts user)
            password: Optional password (if None, prompts user)
            
        Returns:
            Tuple[bool, Optional[str], Optional[str]]: (success, session_token, message)
        """
        try:
            # Get username
            if username is None:
                user_input = input("\n😎 Username:\n> ").strip()
            else:
                user_input = username.strip()
            
            user_input = InputValidator.sanitize_input(user_input)
            
            # Check if account is locked
            is_locked, lock_reason = self.lockout_manager.is_locked(user_input)
            if is_locked:
                print(f"\n\033[91m🔒 {lock_reason}\033[0m")
                SecurityLogger.log_security_violation("LOGIN_ATTEMPT_LOCKED", user_input)
                return False, None, lock_reason
            
            # Get password
            if password is None:
                pwd_input = input("🤫 Password:\n> ").strip()
            else:
                pwd_input = password.strip()
            
            pwd_input = InputValidator.sanitize_input(pwd_input)
            
            # Check if user exists
            if user_input not in self.users:
                self.lockout_manager.record_failed_attempt(user_input)
                attempts_left = self.lockout_manager.get_attempts_remaining(user_input)
                print(f"\n\033[91m❌ User '{user_input}' does not exist\033[0m")
                print(f"\033[94m⚠️  Attempts remaining: {attempts_left}\033[0m")
                SecurityLogger.log_login_attempt(user_input, False, "Unknown user")
                return False, None, "User does not exist"
            
            # Verify password
            stored_hash = self.users[user_input]['password_hash']
            if not PasswordManager.verify_password(pwd_input, stored_hash):
                self.lockout_manager.record_failed_attempt(user_input)
                attempts_left = self.lockout_manager.get_attempts_remaining(user_input)
                print(f"\n\033[91m❌ Incorrect password\033[0m")
                print(f"\033[94m⚠️  Attempts remaining: {attempts_left}\033[0m")
                SecurityLogger.log_login_attempt(user_input, False, "Wrong password")
                return False, None, "Incorrect password"
            
            # Successful login
            self.lockout_manager.record_successful_login(user_input)
            session_token = self.session_manager.create_session(user_input)
            
            # Update user statistics
            self.users[user_input]['last_login'] = datetime.now()
            self.users[user_input]['login_count'] = self.users[user_input].get('login_count', 0) + 1
            
            print("\n\033[92m🎊🎉🪅🪄 Login successful! 🪄🪅🎉🎊\033[0m")
            SecurityLogger.log_login_attempt(user_input, True)
            return True, session_token, "Login successful"
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Login cancelled")
            return False, None, "Cancelled by user"
        except Exception as e:
            error_msg = f"Error during login: {e}"
            print(f"\033[91m❌ {error_msg}\033[0m")
            SecurityLogger.log_event("LOGIN_ERROR", error_msg, severity="ERROR")
            return False, None, error_msg
    
    def change_password(self, username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        """
        Changes a user's password with validation.
        
        Args:
            username: Username
            old_password: Current password
            new_password: New password
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        try:
            if username not in self.users:
                return False, "User does not exist"
            
            # Verify old password
            stored_hash = self.users[username]['password_hash']
            if not PasswordManager.verify_password(old_password, stored_hash):
                SecurityLogger.log_password_change(username, False)
                return False, "Current password is incorrect"
            
            # Validate new password
            is_valid, errors = InputValidator.validate_password_strength(new_password)
            if not is_valid:
                SecurityLogger.log_password_change(username, False)
                return False, "; ".join(errors)
            
            # Update password
            new_hash = PasswordManager.hash_password(new_password)
            self.users[username]['password_hash'] = new_hash
            
            SecurityLogger.log_password_change(username, True)
            return True, "Password changed successfully"
            
        except Exception as e:
            error_msg = f"Error changing password: {e}"
            SecurityLogger.log_event("PASSWORD_CHANGE_ERROR", error_msg, username, "ERROR")
            return False, error_msg
    
    def get_user_info(self, username: str) -> Optional[Dict]:
        """
        Gets user information (without sensitive data).
        
        Args:
            username: Username to get info for
            
        Returns:
            Optional[Dict]: User info or None if not found
        """
        if username not in self.users:
            return None
        
        user_data = self.users[username].copy()
        # Remove sensitive data
        del user_data['password_hash']
        return user_data
    
    def list_users(self) -> List[str]:
        """
        Returns a list of all registered usernames.
        
        Returns:
            List[str]: List of usernames
        """
        return list(self.users.keys())
    
    def cleanup(self) -> None:
        """Performs cleanup tasks like removing expired sessions."""
        expired_count = self.session_manager.cleanup_expired_sessions()
        if expired_count > 0:
            SecurityLogger.log_event("CLEANUP", f"Cleaned up {expired_count} expired sessions")


# ============================================================================
# MODULE 8: USER INTERFACE AND MAIN PROGRAM
# ============================================================================
def display_menu() -> None:
    """Displays the main menu options."""
    print("\n" + "=" * 80)
    print("\033[1m🔐 SECURE LOGIN SYSTEM - MAIN MENU\033[0m")
    print("=" * 80)
    print("1. Create new user account")
    print("2. Login to existing account")
    print("3. Change password (requires login)")
    print("4. View user information")
    print("5. List all users")
    print("6. Exit")
    print("=" * 80)


def main() -> None:
    """
    Main program entry point.
    Provides an interactive menu-driven interface for the login system.
    """
    print("\n" + "=" * 80)
    print("\033[1m🚀 Initializing Secure Login System...\033[0m")
    print("=" * 80)
    
    system = SecureLoginSystem()
    
    # Create initial user
    print("\n📝 First, let's create a user account:")
    system.create_user()
    
    current_session = None
    current_username = None
    
    while True:
        try:
            system.cleanup()  # Cleanup expired sessions periodically
            
            display_menu()
            choice = input("\n👉 Select an option (1-6): ").strip()
            
            if choice == "1":
                # Create user
                system.create_user()
                
            elif choice == "2":
                # Login
                success, session_token, message = system.login()
                if success:
                    current_session = session_token
                    # Get username from session
                    is_valid, username = system.session_manager.validate_session(session_token)
                    if is_valid:
                        current_username = username
                        print(f"\n✅ Logged in as: {current_username}")
                
            elif choice == "3":
                # Change password
                if not current_session or not current_username:
                    print("\n\033[91m❌ You must be logged in to change your password\033[0m")
                    continue
                
                # Verify session
                is_valid, username = system.session_manager.validate_session(current_session)
                if not is_valid:
                    print("\n\033[91m❌ Session expired. Please login again\033[0m")
                    current_session = None
                    current_username = None
                    continue
                
                print(f"\n🔑 Changing password for: {username}")
                old_pwd = input("Enter current password: ").strip()
                new_pwd = input("Enter new password: ").strip()
                
                success, message = system.change_password(username, old_pwd, new_pwd)
                if success:
                    print(f"\n\033[92m✅ {message}\033[0m")
                else:
                    print(f"\n\033[91m❌ {message}\033[0m")
                    
            elif choice == "4":
                # View user info
                if not current_session or not current_username:
                    print("\n\033[91m❌ You must be logged in to view user information\033[0m")
                    continue
                
                is_valid, username = system.session_manager.validate_session(current_session)
                if not is_valid:
                    print("\n\033[91m❌ Session expired. Please login again\033[0m")
                    current_session = None
                    current_username = None
                    continue
                
                user_info = system.get_user_info(username)
                if user_info:
                    print(f"\n📊 User Information for: {username}")
                    print(f"   Created at: {user_info.get('created_at', 'Unknown')}")
                    print(f"   Last login: {user_info.get('last_login', 'Never')}")
                    print(f"   Total logins: {user_info.get('login_count', 0)}")
                else:
                    print("\n\033[91m❌ User not found\033[0m")
                    
            elif choice == "5":
                # List users
                users = system.list_users()
                if users:
                    print(f"\n👥 Registered users ({len(users)}):")
                    for user in users:
                        print(f"   • {user}")
                else:
                    print("\n📭 No users registered yet")
                    
            elif choice == "6":
                # Exit
                print("\n\033[92m👋 Thank you for using Secure Login System! Goodbye! 👋\033[0m")
                SecurityLogger.log_event("SYSTEM_SHUTDOWN", "System shutdown by user")
                break
                
            else:
                print("\n\033[91m❌ Invalid option. Please select 1-6\033[0m")
                
        except KeyboardInterrupt:
            print("\n\n⚠️  Operation cancelled. Use option 6 to exit properly.")
        except Exception as e:
            print(f"\n\033[91m❌ Unexpected error: {e}\033[0m")
            SecurityLogger.log_event("SYSTEM_ERROR", f"Unexpected error: {e}", severity="ERROR")


# ============================================================================
# PROGRAM ENTRY POINT
# ============================================================================
if __name__ == "__main__":
    main()
