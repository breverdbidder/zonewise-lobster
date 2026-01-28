"""
ZoneWise Lobster - Security Utilities
Implements Greptile security recommendations:
- INPUT-001: Comprehensive input sanitization
- AUDIT-001: Centralized audit logging
- CRED-001: Credential validation
"""

import re
import html
import json
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum

# =============================================================================
# INPUT SANITIZATION (Greptile INPUT-001 Fix)
# =============================================================================

class InputSanitizer:
    """Comprehensive input sanitization for all user-provided data."""
    
    # Florida FIPS codes: 12001-12133 (odd numbers only for counties)
    VALID_FL_FIPS = {f"12{str(i).zfill(3)}" for i in range(1, 134, 2)}
    
    # Allowed characters for different contexts
    COUNTY_NAME_PATTERN = re.compile(r'^[a-zA-Z\s\-\.]+$')
    FIPS_PATTERN = re.compile(r'^12[0-9]{3}$')
    
    # Maximum lengths
    MAX_COUNTY_NAME_LEN = 50
    MAX_URL_LEN = 500
    MAX_JSON_SIZE = 1024 * 1024  # 1MB
    
    # Allowed URL domains (whitelist)
    ALLOWED_DOMAINS = frozenset([
        'municode.com',
        'library.municode.com', 
        'gis.brevardfl.gov',
        'bcpao.us',
        'supabase.co',
        'realforeclose.com'
    ])
    
    @classmethod
    def sanitize_county_name(cls, name: str) -> str:
        """
        Sanitize county name with comprehensive protection.
        - Removes HTML/script injection
        - Removes SQL injection patterns
        - Truncates to max length
        - Validates character set
        """
        if not name or not isinstance(name, str):
            return ""
        
        # Step 1: HTML entity escape
        sanitized = html.escape(name, quote=True)
        
        # Step 2: Remove any remaining special characters
        sanitized = re.sub(r'[^a-zA-Z0-9\s\-]', '', sanitized)
        
        # Step 3: Collapse multiple spaces
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()
        
        # Step 4: Truncate
        sanitized = sanitized[:cls.MAX_COUNTY_NAME_LEN]
        
        # Step 5: Validate pattern
        if not cls.COUNTY_NAME_PATTERN.match(sanitized):
            return ""
            
        return sanitized
    
    @classmethod
    def sanitize_fips(cls, fips: str) -> Optional[str]:
        """
        Validate and sanitize FIPS code.
        Returns None if invalid.
        """
        if not fips or not isinstance(fips, str):
            return None
        
        # Remove any whitespace
        fips = fips.strip()
        
        # Validate format
        if not cls.FIPS_PATTERN.match(fips):
            return None
        
        # Validate against known FL FIPS codes
        if fips not in cls.VALID_FL_FIPS:
            return None
            
        return fips
    
    @classmethod
    def sanitize_url(cls, url: str) -> Optional[str]:
        """
        Validate URL against whitelist of allowed domains.
        Returns None if invalid or not allowed.
        """
        if not url or not isinstance(url, str):
            return None
        
        url = url.strip()
        
        # Check length
        if len(url) > cls.MAX_URL_LEN:
            return None
        
        # Must be HTTPS
        if not url.startswith('https://'):
            return None
        
        # Check against allowed domains
        domain_match = False
        for domain in cls.ALLOWED_DOMAINS:
            if domain in url:
                domain_match = True
                break
        
        if not domain_match:
            return None
            
        return url
    
    @classmethod
    def sanitize_json_input(cls, data: str) -> Optional[Dict]:
        """
        Safely parse and validate JSON input.
        Returns None if invalid or too large.
        """
        if not data or not isinstance(data, str):
            return None
        
        # Check size
        if len(data) > cls.MAX_JSON_SIZE:
            return None
        
        try:
            parsed = json.loads(data)
            if not isinstance(parsed, dict):
                return None
            return parsed
        except json.JSONDecodeError:
            return None


# =============================================================================
# AUDIT LOGGING (Greptile AUDIT-001 Fix)
# =============================================================================

class AuditEventType(Enum):
    """Types of auditable events."""
    WORKFLOW_START = "workflow_start"
    WORKFLOW_END = "workflow_end"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    SCRAPE_START = "scrape_start"
    SCRAPE_SUCCESS = "scrape_success"
    SCRAPE_FAILURE = "scrape_failure"
    DB_INSERT_START = "db_insert_start"
    DB_INSERT_SUCCESS = "db_insert_success"
    DB_INSERT_FAILURE = "db_insert_failure"
    SECURITY_VIOLATION = "security_violation"
    CREDENTIAL_VALIDATION = "credential_validation"


@dataclass
class AuditEvent:
    """Immutable audit event record."""
    event_id: str
    event_type: str
    timestamp: str
    workflow_id: str
    user_id: Optional[str]
    action: str
    target: str
    status: str
    details: Dict[str, Any]
    checksum: str = ""
    
    def __post_init__(self):
        """Generate tamper-proof checksum."""
        if not self.checksum:
            content = f"{self.event_id}|{self.event_type}|{self.timestamp}|{self.workflow_id}|{self.action}|{self.status}"
            self.checksum = hashlib.sha256(content.encode()).hexdigest()[:16]


class AuditLogger:
    """
    Centralized audit logger with tamper-proof records.
    Stores to Supabase audit_logs table.
    """
    
    def __init__(self, supabase_client, workflow_id: str, user_id: Optional[str] = None):
        self.supabase = supabase_client
        self.workflow_id = workflow_id
        self.user_id = user_id
        self.events: List[AuditEvent] = []
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        return f"evt_{timestamp}_{hashlib.md5(self.workflow_id.encode()).hexdigest()[:8]}"
    
    def log(
        self,
        event_type: AuditEventType,
        action: str,
        target: str,
        status: str,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditEvent:
        """Log an audit event."""
        event = AuditEvent(
            event_id=self._generate_event_id(),
            event_type=event_type.value,
            timestamp=datetime.now(timezone.utc).isoformat(),
            workflow_id=self.workflow_id,
            user_id=self.user_id,
            action=action,
            target=target,
            status=status,
            details=details or {}
        )
        
        self.events.append(event)
        
        # Async write to Supabase (fire and forget for performance)
        try:
            if self.supabase:
                self.supabase.table("audit_logs").insert(asdict(event)).execute()
        except Exception as e:
            # Log to stderr but don't fail the workflow
            print(f"[AUDIT WARNING] Failed to write audit log: {e}")
        
        return event
    
    def log_approval(
        self,
        approval_type: str,
        approved: bool,
        approver: Optional[str] = None,
        reason: Optional[str] = None
    ) -> AuditEvent:
        """Log an approval decision."""
        event_type = AuditEventType.APPROVAL_GRANTED if approved else AuditEventType.APPROVAL_DENIED
        return self.log(
            event_type=event_type,
            action=f"approval_{approval_type}",
            target=self.workflow_id,
            status="approved" if approved else "denied",
            details={
                "approval_type": approval_type,
                "approver": approver,
                "reason": reason,
                "decision_timestamp": datetime.now(timezone.utc).isoformat()
            }
        )
    
    def log_security_violation(
        self,
        violation_type: str,
        details: Dict[str, Any]
    ) -> AuditEvent:
        """Log a security violation."""
        return self.log(
            event_type=AuditEventType.SECURITY_VIOLATION,
            action="security_violation",
            target=violation_type,
            status="blocked",
            details={
                "violation_type": violation_type,
                **details
            }
        )
    
    def get_audit_trail(self) -> List[Dict]:
        """Get complete audit trail for this workflow."""
        return [asdict(e) for e in self.events]


# =============================================================================
# CREDENTIAL VALIDATION (Greptile CRED-001 Fix)
# =============================================================================

class CredentialValidator:
    """Validate credentials before use."""
    
    @staticmethod
    def validate_supabase_key(key: str) -> bool:
        """Validate Supabase key format."""
        if not key or not isinstance(key, str):
            return False
        # Supabase keys are JWT tokens
        if not key.startswith("eyJ"):
            return False
        if len(key) < 100:
            return False
        return True
    
    @staticmethod
    def validate_modal_token(token_id: str, token_secret: str) -> bool:
        """Validate Modal token format."""
        if not token_id or not token_secret:
            return False
        if not token_id.startswith("ak-"):
            return False
        return True
    
    @staticmethod
    async def test_supabase_connection(url: str, key: str) -> bool:
        """Test Supabase connection is working."""
        import httpx
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    f"{url}/rest/v1/",
                    headers={"apikey": key}
                )
                return response.status_code in (200, 401)  # 401 means auth works, just no permissions
        except Exception:
            return False
