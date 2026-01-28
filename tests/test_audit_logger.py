"""
ZoneWise Lobster - Audit Logger Unit Tests

Granular unit tests for AuditLogger and related classes.
Tests audit event creation, checksums, and persistence.

Run with: pytest tests/test_audit_logger.py -v
"""

import pytest
import hashlib
from datetime import datetime, timezone
from unittest.mock import MagicMock
from typing import Any, Dict


class TestAuditEventType:
    """Tests for AuditEventType enum."""
    
    def test_workflow_events(self) -> None:
        """Test workflow event types exist."""
        from scripts.security_utils import AuditEventType
        
        assert AuditEventType.WORKFLOW_START.value == "workflow_start"
        assert AuditEventType.WORKFLOW_END.value == "workflow_end"
    
    def test_scrape_events(self) -> None:
        """Test scrape event types exist."""
        from scripts.security_utils import AuditEventType
        
        assert AuditEventType.SCRAPE_START.value == "scrape_start"
        assert AuditEventType.SCRAPE_SUCCESS.value == "scrape_success"
        assert AuditEventType.SCRAPE_FAILURE.value == "scrape_failure"
    
    def test_security_events(self) -> None:
        """Test security event types exist."""
        from scripts.security_utils import AuditEventType
        
        assert AuditEventType.SECURITY_VIOLATION.value == "security_violation"
        assert AuditEventType.CREDENTIAL_VALIDATION.value == "credential_validation"


class TestAuditEvent:
    """Tests for AuditEvent dataclass."""
    
    def test_event_creation(self) -> None:
        """Test creating an audit event."""
        from scripts.security_utils import AuditEvent, AuditEventType
        
        event = AuditEvent(
            event_id="evt_test_123",
            event_type=AuditEventType.WORKFLOW_START,
            timestamp=datetime.now(timezone.utc),
            workflow_id="wf_test",
            action="test_action",
            target="test_target",
            status="success",
            details={"key": "value"},
            checksum="abc123def456"
        )
        
        assert event.event_id == "evt_test_123"
        assert event.event_type == AuditEventType.WORKFLOW_START
        assert event.workflow_id == "wf_test"
        assert event.status == "success"
    
    def test_event_default_details(self) -> None:
        """Test event has default empty details."""
        from scripts.security_utils import AuditEvent, AuditEventType
        
        event = AuditEvent(
            event_id="evt_test",
            event_type=AuditEventType.SCRAPE_START,
            timestamp=datetime.now(timezone.utc),
            workflow_id="wf_test",
            action="scrape",
            target="url",
            status="started",
            checksum="checksum"
        )
        
        assert event.details == {}


class TestAuditLogger:
    """Tests for AuditLogger class."""
    
    @pytest.fixture
    def mock_supabase(self) -> MagicMock:
        """Create mock Supabase client with call tracking."""
        mock = MagicMock()
        mock.inserted = []
        
        def track_insert(record: Dict) -> MagicMock:
            mock.inserted.append(record)
            return MagicMock(execute=lambda: {"data": [record]})
        
        mock.table.return_value.insert = track_insert
        return mock
    
    def test_log_creates_event(self, mock_supabase: MagicMock) -> None:
        """Test log() creates an audit event."""
        from scripts.security_utils import AuditLogger, AuditEventType
        
        logger = AuditLogger(mock_supabase, "wf_test_001")
        
        event = logger.log(
            event_type=AuditEventType.WORKFLOW_START,
            action="start_workflow",
            target="scrape_counties",
            status="started"
        )
        
        assert event.workflow_id == "wf_test_001"
        assert event.action == "start_workflow"
        assert event.status == "started"
    
    def test_log_generates_event_id(self, mock_supabase: MagicMock) -> None:
        """Test log() generates unique event ID."""
        from scripts.security_utils import AuditLogger, AuditEventType
        
        logger = AuditLogger(mock_supabase, "wf_test")
        
        event = logger.log(
            event_type=AuditEventType.SCRAPE_START,
            action="scrape",
            target="url",
            status="started"
        )
        
        assert event.event_id.startswith("evt_")
        assert "wf_test" in event.event_id
    
    def test_log_generates_checksum(self, mock_supabase: MagicMock) -> None:
        """Test log() generates checksum."""
        from scripts.security_utils import AuditLogger, AuditEventType
        
        logger = AuditLogger(mock_supabase, "wf_test")
        
        event = logger.log(
            event_type=AuditEventType.SCRAPE_SUCCESS,
            action="scrape",
            target="url",
            status="success"
        )
        
        assert len(event.checksum) == 16
        assert all(c in '0123456789abcdef' for c in event.checksum)
    
    def test_log_checksums_unique(self, mock_supabase: MagicMock) -> None:
        """Test different events have unique checksums."""
        from scripts.security_utils import AuditLogger, AuditEventType
        
        logger = AuditLogger(mock_supabase, "wf_test")
        
        checksums = set()
        for i in range(10):
            event = logger.log(
                event_type=AuditEventType.SCRAPE_START,
                action=f"action_{i}",
                target=f"target_{i}",
                status="started"
            )
            checksums.add(event.checksum)
        
        assert len(checksums) == 10
    
    def test_log_persists_to_supabase(self, mock_supabase: MagicMock) -> None:
        """Test log() persists to Supabase."""
        from scripts.security_utils import AuditLogger, AuditEventType
        
        logger = AuditLogger(mock_supabase, "wf_persist_test")
        
        logger.log(
            event_type=AuditEventType.DATA_INSERTED,
            action="insert",
            target="districts",
            status="success",
            details={"count": 15}
        )
        
        assert len(mock_supabase.inserted) == 1
        record = mock_supabase.inserted[0]
        assert record["workflow_id"] == "wf_persist_test"
        assert record["event_type"] == "data_inserted"
    
    def test_log_security_violation(self, mock_supabase: MagicMock) -> None:
        """Test log_security_violation() helper."""
        from scripts.security_utils import AuditLogger, AuditEventType
        
        logger = AuditLogger(mock_supabase, "wf_security_test")
        
        event = logger.log_security_violation(
            violation_type="sql_injection",
            details={"input": "malicious", "blocked": True}
        )
        
        assert event.event_type == AuditEventType.SECURITY_VIOLATION
        assert event.status == "blocked"
        assert "sql_injection" in event.details["violation_type"]
    
    def test_log_approval(self, mock_supabase: MagicMock) -> None:
        """Test log_approval() helper."""
        from scripts.security_utils import AuditLogger
        
        logger = AuditLogger(mock_supabase, "wf_approval_test")
        
        event = logger.log_approval(
            approval_type="pre_scrape",
            approved=True,
            approver="admin@example.com",
            reason="Approved for testing"
        )
        
        assert event.details["approval_type"] == "pre_scrape"
        assert event.details["approved"] is True
        assert event.details["approver"] == "admin@example.com"
    
    def test_log_with_details(self, mock_supabase: MagicMock) -> None:
        """Test log() with custom details."""
        from scripts.security_utils import AuditLogger, AuditEventType
        
        logger = AuditLogger(mock_supabase, "wf_details_test")
        
        event = logger.log(
            event_type=AuditEventType.SCRAPE_SUCCESS,
            action="scrape",
            target="https://municode.com/fl/brevard",
            status="success",
            details={
                "districts_found": 25,
                "quality_score": 85,
                "duration_seconds": 12.5
            }
        )
        
        assert event.details["districts_found"] == 25
        assert event.details["quality_score"] == 85


class TestChecksumIntegrity:
    """Tests for checksum generation and verification."""
    
    def test_checksum_format(self) -> None:
        """Test checksum is 16 hex characters."""
        content = "test|content|for|checksum"
        checksum = hashlib.sha256(content.encode()).hexdigest()[:16]
        
        assert len(checksum) == 16
        assert all(c in '0123456789abcdef' for c in checksum)
    
    def test_checksum_deterministic(self) -> None:
        """Test same content produces same checksum."""
        content = "event_123|workflow_start|wf_test|scrape|success"
        
        checksum1 = hashlib.sha256(content.encode()).hexdigest()[:16]
        checksum2 = hashlib.sha256(content.encode()).hexdigest()[:16]
        
        assert checksum1 == checksum2
    
    def test_checksum_sensitive_to_changes(self) -> None:
        """Test checksum changes with content changes."""
        content1 = "event_123|workflow_start|wf_test|scrape|success"
        content2 = "event_123|workflow_start|wf_test|scrape|failure"
        
        checksum1 = hashlib.sha256(content1.encode()).hexdigest()[:16]
        checksum2 = hashlib.sha256(content2.encode()).hexdigest()[:16]
        
        assert checksum1 != checksum2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
