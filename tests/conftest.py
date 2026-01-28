"""
Pytest configuration and shared fixtures for ZoneWise Lobster tests.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))


@pytest.fixture
def mock_supabase():
    """
    Create a mock Supabase client for testing.
    
    Returns a MagicMock that simulates Supabase client behavior
    for table operations, inserts, and upserts.
    """
    mock = MagicMock()
    
    # Configure table().insert().execute() chain
    mock.table.return_value.insert.return_value.execute.return_value = {
        "data": [{"id": 1}],
        "error": None
    }
    
    # Configure table().upsert().execute() chain
    mock.table.return_value.upsert.return_value.execute.return_value = {
        "data": [{"id": 1}],
        "error": None
    }
    
    # Configure table().select().eq().single().execute() chain
    mock.table.return_value.select.return_value.eq.return_value.single.return_value.execute.return_value = {
        "data": None,
        "error": None
    }
    
    return mock


@pytest.fixture
def sample_fips_codes():
    """Return sample valid Florida FIPS codes for testing."""
    return [
        "12001",  # Alachua
        "12009",  # Brevard
        "12011",  # Broward
        "12057",  # Hillsborough
        "12086",  # Miami-Dade
        "12095",  # Orange
        "12099",  # Palm Beach
        "12103",  # Pinellas
    ]


@pytest.fixture
def sample_county_names():
    """Return sample valid Florida county names for testing."""
    return [
        "Brevard",
        "Miami-Dade",
        "Hillsborough",
        "Orange",
        "Palm Beach",
        "Pinellas",
        "Duval",
        "St. Johns",
    ]


@pytest.fixture
def sample_urls():
    """Return sample valid URLs for testing."""
    return {
        "valid": [
            "https://municode.com/path",
            "https://library.municode.com/fl/brevard",
            "https://supabase.co/rest/v1/",
            "https://gis.brevardfl.gov/api",
            "https://bcpao.us/PropertySearch",
        ],
        "invalid": [
            "http://municode.com",  # HTTP not HTTPS
            "https://evil.com/steal",  # Not whitelisted
            "ftp://municode.com",  # Wrong protocol
            "",  # Empty
            None,  # None
        ]
    }


@pytest.fixture
def sample_jwt():
    """Return a sample valid JWT for testing."""
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRlc3QiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNjAwMDAwMDAwLCJleHAiOjIwMDAwMDAwMDB9.test_signature_with_enough_length_to_pass_validation"
