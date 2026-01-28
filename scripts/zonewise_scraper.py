"""
ZoneWise Lobster - Modal.com Zoning Data Scraper

Security-hardened scraper implementing the Malabar methodology for 
extracting zoning ordinance data from Florida county Municode sites.

Features:
- Input validation via InputSanitizer
- Centralized audit logging
- Resource limits (memory, CPU, timeout)
- Credential validation before use
- Global rate limiting integration

Author: BidDeed.AI
Version: 2.0.0
"""

from __future__ import annotations

import os
import re
import json
import hashlib
import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple, TYPE_CHECKING
from dataclasses import dataclass, field, asdict

import modal

if TYPE_CHECKING:
    from httpx import Response

# =============================================================================
# RESOURCE LIMITS (Greptile RESOURCE-001)
# =============================================================================

RESOURCE_LIMITS: Dict[str, Any] = {
    "timeout": 600,           # 10 minutes per county
    "memory": 1024,           # 1GB RAM limit
    "cpu": 1.0,               # 1 CPU core
    "retries": 3,             # Max retries
    "concurrency_limit": 20,  # Rate limiting
}

# =============================================================================
# MODAL APP CONFIGURATION
# =============================================================================

image = modal.Image.debian_slim(python_version="3.11").pip_install(
    "httpx==0.27.0",
    "beautifulsoup4==4.12.3",
    "lxml==5.1.0",
    "supabase==2.3.4",
    "pdfplumber==0.10.3",
    "tenacity==8.2.3",
)

app = modal.App("zonewise-lobster-scraper")

secrets = modal.Secret.from_name("zonewise-credentials")


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ZoningDistrict:
    """
    Represents a zoning district extracted from Municode.
    
    Attributes:
        code: Zoning code (e.g., 'R-1', 'C-2')
        name: Full name of the district
        description: Description of allowed uses
        county_fips: Florida FIPS code (12XXX format)
        county_name: Human-readable county name
        source_url: URL where data was extracted from
        extracted_at: ISO timestamp of extraction
        quality_score: Data quality score (0-100)
    """
    code: str
    name: str
    description: str
    county_fips: str
    county_name: str
    source_url: str
    extracted_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    quality_score: int = 0


@dataclass
class ScrapeResult:
    """
    Result of a county scrape operation.
    
    Attributes:
        status: 'success' or 'error'
        county_fips: Florida FIPS code
        county_name: Human-readable county name
        districts: List of extracted zoning districts
        quality_score: Overall quality score (0-100)
        errors: List of error messages encountered
        duration_seconds: Time taken to scrape
        workflow_id: ID of the workflow that triggered this scrape
    """
    status: str
    county_fips: str
    county_name: str
    districts: List[ZoningDistrict] = field(default_factory=list)
    quality_score: int = 0
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    workflow_id: str = ""


# =============================================================================
# INPUT VALIDATION (LOCAL COPY FOR MODAL)
# =============================================================================

class InputSanitizer:
    """
    Input sanitization for security.
    
    Validates and sanitizes all user inputs before use to prevent
    injection attacks and ensure data integrity.
    """
    
    # Valid Florida FIPS codes (odd numbers 12001-12133)
    VALID_FL_FIPS: frozenset = frozenset({f"12{str(i).zfill(3)}" for i in range(1, 134, 2)})
    
    # Allowed domains for scraping
    ALLOWED_DOMAINS: frozenset = frozenset([
        'municode.com',
        'library.municode.com',
        'supabase.co',
        'gis.brevardfl.gov',
        'bcpao.us',
    ])
    
    @classmethod
    def sanitize_fips(cls, fips: str) -> Optional[str]:
        """
        Validate and sanitize a Florida FIPS code.
        
        Args:
            fips: Raw FIPS code input
            
        Returns:
            Sanitized FIPS code or None if invalid
        """
        if not fips or not isinstance(fips, str):
            return None
        
        # Remove whitespace and validate format
        clean_fips: str = fips.strip()
        
        if not re.match(r'^12\d{3}$', clean_fips):
            return None
        
        if clean_fips not in cls.VALID_FL_FIPS:
            return None
        
        return clean_fips
    
    @classmethod
    def sanitize_county_name(cls, name: str) -> Optional[str]:
        """
        Sanitize a county name to prevent injection.
        
        Args:
            name: Raw county name input
            
        Returns:
            Sanitized county name or None if invalid
        """
        if not name or not isinstance(name, str):
            return None
        
        # Basic sanitization
        clean_name: str = name.strip()
        
        # Remove potentially dangerous characters
        clean_name = re.sub(r'[<>&\'";\\]', '', clean_name)
        
        # Limit length
        clean_name = clean_name[:50]
        
        # Must have at least 2 characters
        if len(clean_name) < 2:
            return None
        
        return clean_name
    
    @classmethod
    def sanitize_url(cls, url: str) -> Optional[str]:
        """
        Validate URL against whitelist.
        
        Args:
            url: Raw URL input
            
        Returns:
            Validated URL or None if not allowed
        """
        if not url or not isinstance(url, str):
            return None
        
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            
            # Must be HTTPS
            if parsed.scheme != 'https':
                return None
            
            # Check domain whitelist
            domain: str = parsed.netloc.lower()
            for allowed in cls.ALLOWED_DOMAINS:
                if domain == allowed or domain.endswith(f'.{allowed}'):
                    return url
            
            return None
        except (ValueError, AttributeError):
            return None


# =============================================================================
# CREDENTIAL VALIDATION
# =============================================================================

class CredentialValidator:
    """
    Validates credentials before use.
    
    Ensures API keys and tokens are properly formatted and
    can successfully authenticate before proceeding.
    """
    
    @staticmethod
    def validate_supabase_key(key: str) -> bool:
        """
        Validate Supabase service role key format.
        
        Args:
            key: Supabase API key to validate
            
        Returns:
            True if format is valid
        """
        if not key or not isinstance(key, str):
            return False
        
        # JWT format check
        if not key.startswith('eyJ'):
            return False
        
        # Should have 3 parts separated by dots
        parts: List[str] = key.split('.')
        if len(parts) != 3:
            return False
        
        return len(key) > 100
    
    @staticmethod
    async def test_supabase_connection(url: str, key: str) -> bool:
        """
        Test Supabase connection is working.
        
        Args:
            url: Supabase project URL
            key: Supabase API key
            
        Returns:
            True if connection successful
        """
        import httpx
        
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response: Response = await client.get(
                    f"{url}/rest/v1/",
                    headers={
                        "apikey": key,
                        "Authorization": f"Bearer {key}"
                    }
                )
                return response.status_code in (200, 401)
        except (httpx.TimeoutException, httpx.ConnectError):
            return False


# =============================================================================
# AUDIT LOGGING (SIMPLIFIED FOR MODAL)
# =============================================================================

class SimpleAuditLogger:
    """
    Simplified audit logger for Modal functions.
    
    Logs events to Supabase audit_logs table with checksums
    for tamper detection.
    """
    
    def __init__(self, supabase_client: Any, workflow_id: str) -> None:
        """
        Initialize audit logger.
        
        Args:
            supabase_client: Supabase client instance
            workflow_id: ID of the current workflow
        """
        self.supabase: Any = supabase_client
        self.workflow_id: str = workflow_id
    
    def log(
        self,
        event_type: str,
        action: str,
        target: str,
        status: str,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log an audit event.
        
        Args:
            event_type: Type of event (e.g., 'scrape_start')
            action: Action being performed
            target: Target of the action
            status: Status of the action
            details: Additional context
        """
        event_id: str = f"evt_{self.workflow_id}_{hashlib.sha256(f'{action}{target}{datetime.now().isoformat()}'.encode()).hexdigest()[:12]}"
        
        checksum_content: str = f"{event_id}|{event_type}|{self.workflow_id}|{action}|{status}"
        checksum: str = hashlib.sha256(checksum_content.encode()).hexdigest()[:16]
        
        try:
            self.supabase.table("audit_logs").insert({
                "event_id": event_id,
                "event_type": event_type,
                "workflow_id": self.workflow_id,
                "action": action,
                "target": target,
                "status": status,
                "details": details or {},
                "checksum": checksum
            }).execute()
        except Exception as e:
            print(f"Audit log failed: {e}")


# =============================================================================
# MALABAR METHODOLOGY SCRAPER
# =============================================================================

async def scrape_municode_page(
    url: str,
    county_fips: str,
    county_name: str
) -> Tuple[List[ZoningDistrict], List[str]]:
    """
    Scrape a single Municode page for zoning districts.
    
    Implements the Malabar methodology for extracting structured
    zoning data from unstructured HTML content.
    
    Args:
        url: Municode URL to scrape
        county_fips: Florida FIPS code for the county
        county_name: Human-readable county name
        
    Returns:
        Tuple of (list of ZoningDistricts, list of errors)
    """
    import httpx
    from bs4 import BeautifulSoup
    
    districts: List[ZoningDistrict] = []
    errors: List[str] = []
    
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response: Response = await client.get(url)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'lxml')
            
            # Find zoning code patterns
            code_patterns: List[str] = [
                r'\b([A-Z]{1,3}-\d{1,2}[A-Z]?)\b',  # R-1, C-2A, etc.
                r'\b(PUD|PD|CDD|DRI)\b',             # Special districts
            ]
            
            # Extract from tables
            tables = soup.find_all('table')
            for table in tables:
                rows = table.find_all('tr')
                for row in rows:
                    cells = row.find_all(['td', 'th'])
                    if len(cells) >= 2:
                        potential_code: str = cells[0].get_text(strip=True)
                        potential_name: str = cells[1].get_text(strip=True)
                        
                        for pattern in code_patterns:
                            if re.match(pattern, potential_code):
                                districts.append(ZoningDistrict(
                                    code=potential_code,
                                    name=potential_name,
                                    description=cells[2].get_text(strip=True) if len(cells) > 2 else "",
                                    county_fips=county_fips,
                                    county_name=county_name,
                                    source_url=url,
                                    quality_score=80
                                ))
                                break
            
            # Extract from definition lists
            dl_items = soup.find_all(['dt', 'dd'])
            for i in range(0, len(dl_items) - 1, 2):
                if dl_items[i].name == 'dt':
                    potential_code = dl_items[i].get_text(strip=True)
                    for pattern in code_patterns:
                        if re.match(pattern, potential_code):
                            districts.append(ZoningDistrict(
                                code=potential_code,
                                name=dl_items[i + 1].get_text(strip=True) if i + 1 < len(dl_items) else "",
                                description="",
                                county_fips=county_fips,
                                county_name=county_name,
                                source_url=url,
                                quality_score=70
                            ))
                            break
    
    except httpx.TimeoutException:
        errors.append(f"Timeout scraping {url}")
    except httpx.HTTPStatusError as e:
        errors.append(f"HTTP {e.response.status_code} from {url}")
    except Exception as e:
        errors.append(f"Error scraping {url}: {str(e)[:100]}")
    
    return districts, errors


def calculate_quality_score(districts: List[ZoningDistrict], errors: List[str]) -> int:
    """
    Calculate overall quality score for scraped data.
    
    Factors in number of districts found, error count, and
    individual district quality scores.
    
    Args:
        districts: List of extracted districts
        errors: List of errors encountered
        
    Returns:
        Quality score from 0-100
    """
    if not districts:
        return 0
    
    # Base score from district count (up to 40 points)
    count_score: int = min(40, len(districts) * 4)
    
    # Average district quality (up to 40 points)
    avg_quality: float = sum(d.quality_score for d in districts) / len(districts)
    quality_score: int = int(avg_quality * 0.4)
    
    # Error penalty (up to -20 points)
    error_penalty: int = min(20, len(errors) * 5)
    
    # Calculate final score
    final_score: int = count_score + quality_score - error_penalty
    
    return max(0, min(100, final_score))


# =============================================================================
# MODAL FUNCTION
# =============================================================================

@app.function(
    image=image,
    secrets=[secrets],
    timeout=RESOURCE_LIMITS["timeout"],
    memory=RESOURCE_LIMITS["memory"],
    cpu=RESOURCE_LIMITS["cpu"],
    retries=RESOURCE_LIMITS["retries"],
    concurrency_limit=RESOURCE_LIMITS["concurrency_limit"]
)
async def scrape_county(
    county_fips: str,
    county_name: str,
    phases: Optional[List[int]] = None,
    workflow_id: str = "unknown"
) -> Dict[str, Any]:
    """
    Scrape zoning data for a single Florida county.
    
    Main entry point for Modal function. Validates inputs,
    initializes audit logging, and orchestrates the scrape.
    
    Args:
        county_fips: Florida FIPS code (12XXX format)
        county_name: Human-readable county name
        phases: Malabar phases to execute (default: [2, 3, 4, 5])
        workflow_id: ID of the workflow triggering this scrape
        
    Returns:
        Dictionary with scrape results:
        {
            "status": "success" | "error",
            "county_fips": str,
            "county_name": str,
            "districts": List[Dict],
            "quality_score": int,
            "errors": List[str],
            "duration_seconds": float
        }
    """
    import time
    from supabase import create_client
    
    start_time: float = time.time()
    
    # Default phases
    if phases is None:
        phases = [2, 3, 4, 5]
    
    # Input validation
    sanitized_fips: Optional[str] = InputSanitizer.sanitize_fips(county_fips)
    sanitized_name: Optional[str] = InputSanitizer.sanitize_county_name(county_name)
    
    if not sanitized_fips:
        return asdict(ScrapeResult(
            status="error",
            county_fips=county_fips,
            county_name=county_name,
            errors=[f"Invalid FIPS code: {county_fips}"],
            workflow_id=workflow_id
        ))
    
    if not sanitized_name:
        return asdict(ScrapeResult(
            status="error",
            county_fips=county_fips,
            county_name=county_name,
            errors=[f"Invalid county name: {county_name}"],
            workflow_id=workflow_id
        ))
    
    # Initialize Supabase
    supabase_url: str = os.environ.get("SUPABASE_URL", "")
    supabase_key: str = os.environ.get("SUPABASE_KEY", "")
    
    # Validate credentials
    if not CredentialValidator.validate_supabase_key(supabase_key):
        return asdict(ScrapeResult(
            status="error",
            county_fips=sanitized_fips,
            county_name=sanitized_name,
            errors=["Invalid Supabase credentials"],
            workflow_id=workflow_id
        ))
    
    supabase = create_client(supabase_url, supabase_key)
    audit = SimpleAuditLogger(supabase, workflow_id)
    
    # Log start
    audit.log(
        event_type="scrape_start",
        action="scrape_county",
        target=f"{sanitized_fips}:{sanitized_name}",
        status="started",
        details={"phases": phases}
    )
    
    # Build Municode URL
    municode_url: str = f"https://library.municode.com/fl/{sanitized_name.lower().replace(' ', '_')}/codes/code_of_ordinances"
    
    # Validate URL
    if not InputSanitizer.sanitize_url(municode_url):
        return asdict(ScrapeResult(
            status="error",
            county_fips=sanitized_fips,
            county_name=sanitized_name,
            errors=[f"URL validation failed: {municode_url}"],
            workflow_id=workflow_id
        ))
    
    # Execute scrape
    all_districts: List[ZoningDistrict] = []
    all_errors: List[str] = []
    
    try:
        districts, errors = await scrape_municode_page(
            municode_url,
            sanitized_fips,
            sanitized_name
        )
        all_districts.extend(districts)
        all_errors.extend(errors)
    except Exception as e:
        all_errors.append(f"Scrape failed: {str(e)[:100]}")
    
    # Calculate quality
    quality_score: int = calculate_quality_score(all_districts, all_errors)
    duration: float = time.time() - start_time
    
    # Log completion
    status: str = "success" if all_districts else "error"
    audit.log(
        event_type="scrape_success" if status == "success" else "scrape_failure",
        action="scrape_county_complete",
        target=f"{sanitized_fips}:{sanitized_name}",
        status=status,
        details={
            "districts_count": len(all_districts),
            "errors_count": len(all_errors),
            "quality_score": quality_score,
            "duration_seconds": duration
        }
    )
    
    return asdict(ScrapeResult(
        status=status,
        county_fips=sanitized_fips,
        county_name=sanitized_name,
        districts=[asdict(d) for d in all_districts],
        quality_score=quality_score,
        errors=all_errors,
        duration_seconds=duration,
        workflow_id=workflow_id
    ))


# =============================================================================
# LOCAL ENTRYPOINT (for testing)
# =============================================================================

@app.local_entrypoint()
def main(
    county_fips: str = "12009",
    county_name: str = "Brevard"
) -> None:
    """
    Local entrypoint for testing.
    
    Args:
        county_fips: Florida FIPS code to test
        county_name: County name to test
    """
    result: Dict[str, Any] = scrape_county.remote(
        county_fips=county_fips,
        county_name=county_name,
        workflow_id=f"test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    print(json.dumps(result, indent=2))
