"""
ZoneWise Lobster - InputSanitizer Unit Tests

Granular unit tests specifically for InputSanitizer class.
Tests all input validation methods with comprehensive edge cases.

Run with: pytest tests/test_input_sanitizer.py -v
"""

import pytest
from typing import Optional


class TestSanitizeFips:
    """Tests for InputSanitizer.sanitize_fips()."""
    
    def test_valid_brevard_county(self) -> None:
        """Test Brevard County FIPS code."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_fips("12009") == "12009"
    
    def test_valid_miami_dade_county(self) -> None:
        """Test Miami-Dade County FIPS code."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_fips("12086") == "12086"
    
    def test_valid_orange_county(self) -> None:
        """Test Orange County FIPS code."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_fips("12095") == "12095"
    
    def test_valid_first_county(self) -> None:
        """Test first Florida county FIPS."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_fips("12001") == "12001"
    
    def test_valid_last_county(self) -> None:
        """Test last Florida county FIPS."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_fips("12133") == "12133"
    
    def test_invalid_even_number(self) -> None:
        """Test even FIPS codes are rejected (FL uses odd numbers)."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_fips("12002") is None
        assert InputSanitizer.sanitize_fips("12010") is None
    
    def test_invalid_wrong_state(self) -> None:
        """Test non-Florida state codes are rejected."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_fips("13001") is None  # Georgia
        assert InputSanitizer.sanitize_fips("06001") is None  # California
    
    def test_invalid_too_short(self) -> None:
        """Test short FIPS codes are rejected."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_fips("12") is None
        assert InputSanitizer.sanitize_fips("1200") is None
    
    def test_invalid_too_long(self) -> None:
        """Test long FIPS codes are rejected."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_fips("120091") is None
        assert InputSanitizer.sanitize_fips("1200912345") is None
    
    def test_invalid_letters(self) -> None:
        """Test FIPS codes with letters are rejected."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_fips("12ABC") is None
        assert InputSanitizer.sanitize_fips("ABCDE") is None
    
    def test_sql_injection_drop_table(self) -> None:
        """Test SQL injection DROP TABLE is blocked."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_fips("12009; DROP TABLE users--") is None
    
    def test_sql_injection_or_1_equals_1(self) -> None:
        """Test SQL injection OR 1=1 is blocked."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_fips("12009' OR '1'='1") is None
    
    def test_sql_injection_union_select(self) -> None:
        """Test SQL injection UNION SELECT is blocked."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_fips("12009 UNION SELECT * FROM passwords") is None
    
    def test_whitespace_handling(self) -> None:
        """Test whitespace is trimmed."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_fips("  12009  ") == "12009"
        assert InputSanitizer.sanitize_fips("\t12009\n") == "12009"
    
    def test_empty_string(self) -> None:
        """Test empty string is rejected."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_fips("") is None
    
    def test_none_input(self) -> None:
        """Test None input is handled."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_fips(None) is None  # type: ignore


class TestSanitizeCountyName:
    """Tests for InputSanitizer.sanitize_county_name()."""
    
    def test_valid_simple_name(self) -> None:
        """Test simple county name."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_county_name("Brevard") == "Brevard"
    
    def test_valid_hyphenated_name(self) -> None:
        """Test hyphenated county name."""
        from scripts.security_utils import InputSanitizer
        result = InputSanitizer.sanitize_county_name("Miami-Dade")
        assert result == "Miami-Dade"
    
    def test_valid_name_with_period(self) -> None:
        """Test county name with period."""
        from scripts.security_utils import InputSanitizer
        result = InputSanitizer.sanitize_county_name("St. Johns")
        assert "St" in result
    
    def test_xss_script_tag(self) -> None:
        """Test XSS script tag is sanitized."""
        from scripts.security_utils import InputSanitizer
        result = InputSanitizer.sanitize_county_name("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "</script>" not in result
    
    def test_xss_img_onerror(self) -> None:
        """Test XSS img onerror is sanitized."""
        from scripts.security_utils import InputSanitizer
        result = InputSanitizer.sanitize_county_name("<img src=x onerror=alert(1)>")
        assert "onerror" not in result or "<" not in result
    
    def test_xss_javascript_protocol(self) -> None:
        """Test XSS javascript: protocol is sanitized."""
        from scripts.security_utils import InputSanitizer
        result = InputSanitizer.sanitize_county_name("javascript:alert(1)")
        # Should either reject or sanitize
        assert result is None or "javascript:" not in result
    
    def test_length_limit_enforced(self) -> None:
        """Test 50 character limit is enforced."""
        from scripts.security_utils import InputSanitizer
        long_name = "A" * 100
        result = InputSanitizer.sanitize_county_name(long_name)
        assert result is not None
        assert len(result) <= 50
    
    def test_minimum_length(self) -> None:
        """Test minimum 2 character requirement."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_county_name("") is None
        assert InputSanitizer.sanitize_county_name("A") is None
        assert InputSanitizer.sanitize_county_name("AB") == "AB"
    
    def test_special_chars_removed(self) -> None:
        """Test dangerous special characters are removed."""
        from scripts.security_utils import InputSanitizer
        result = InputSanitizer.sanitize_county_name("Brevard<>\"';")
        assert "<" not in result
        assert ">" not in result
        assert '"' not in result
        assert "'" not in result
        assert ";" not in result


class TestSanitizeUrl:
    """Tests for InputSanitizer.sanitize_url()."""
    
    def test_valid_municode_url(self) -> None:
        """Test valid Municode URL."""
        from scripts.security_utils import InputSanitizer
        url = "https://municode.com/fl/brevard"
        assert InputSanitizer.sanitize_url(url) == url
    
    def test_valid_library_municode_url(self) -> None:
        """Test valid library.municode.com URL."""
        from scripts.security_utils import InputSanitizer
        url = "https://library.municode.com/fl/brevard"
        assert InputSanitizer.sanitize_url(url) is not None
    
    def test_valid_supabase_url(self) -> None:
        """Test valid Supabase URL."""
        from scripts.security_utils import InputSanitizer
        url = "https://supabase.co/rest/v1/"
        assert InputSanitizer.sanitize_url(url) is not None
    
    def test_http_rejected(self) -> None:
        """Test HTTP (non-HTTPS) is rejected."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_url("http://municode.com") is None
    
    def test_invalid_domain_rejected(self) -> None:
        """Test non-whitelisted domains are rejected."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_url("https://evil.com/steal") is None
        assert InputSanitizer.sanitize_url("https://malware.io/inject") is None
    
    def test_ftp_rejected(self) -> None:
        """Test FTP protocol is rejected."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_url("ftp://municode.com/file") is None
    
    def test_empty_url(self) -> None:
        """Test empty URL is rejected."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_url("") is None
    
    def test_none_url(self) -> None:
        """Test None URL is handled."""
        from scripts.security_utils import InputSanitizer
        assert InputSanitizer.sanitize_url(None) is None  # type: ignore


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
