"""
Test suite for sanctions_check.py
Covers: clean pass, OFAC/UN detection, malformed inputs, performance
"""

import pytest
import time
from datetime import datetime
from sanctions_check import (
    sanctions_check,
    InputValidationError,
    SanctionsScreeningError
)


class TestCleanTransaction:
    """Test clean transactions with no sanctions matches."""

    def test_clean_transaction_pass(self):
        """Clean transaction should return status=pass, confidence=0.0, empty match_list."""
        result = sanctions_check(
            customer_id="CUST-123456",
            counterparty_details={
                "name": "Global Trade Partners LLC",
                "country": "AE",
                "account": "AE070331234567890123456"
            },
            transaction_amount=50000.0
        )

        assert result["screened"] is True, "Screening should execute successfully"
        assert result["status"] == "pass", "Clean transaction should pass"
        assert result["confidence"] == 0.0, "No match should have 0.0 confidence"
        assert result["match_list"] == [], "Match list should be empty"
        assert result["step"] == 3, "Sanctions screening is step 3"
        assert result["name"] == "sanctions_screening"
        assert "SANC-" in result["reference_id"], "Should have valid reference ID"
        assert result["processing_time_ms"] >= 0, "Should record processing time"

    def test_clean_transaction_with_aml_context(self):
        """Clean transaction with AML context should still pass."""
        aml_result = {
            "status": "pass",
            "risk_score": 0.25,
            "flags": []
        }

        result = sanctions_check(
            customer_id="CUST-789012",
            counterparty_details={
                "name": "Legitimate Business Corp",
                "country": "SG"
            },
            transaction_amount=25000.0,
            aml_result=aml_result
        )

        assert result["status"] == "pass"
        assert result["confidence"] == 0.0
        assert len(result["match_list"]) == 0


class TestOFACMatchDetection:
    """Test OFAC sanctions list matching."""

    def test_ofac_match_triggers_flag(self):
        """Name containing 'SANCTIONED' should trigger OFAC_SDN match."""
        result = sanctions_check(
            customer_id="CUST-999888",
            counterparty_details={
                "name": "SANCTIONED ENTITY LLC",
                "country": "RU"
            },
            transaction_amount=100000.0
        )

        assert result["screened"] is True
        assert result["status"] == "blocked", "High confidence match should block"
        assert result["confidence"] > 0.8, "OFAC match should have high confidence"
        assert len(result["match_list"]) > 0, "Should have at least one match"

        # Check match details
        ofac_match = result["match_list"][0]
        assert ofac_match["list_source"] == "OFAC_SDN"
        assert ofac_match["matched_name"] == "SANCTIONED ENTITY LLC"
        assert ofac_match["match_type"] in ["exact", "fuzzy"]
        assert ofac_match["score"] > 0.8
        assert "list_entry_id" in ofac_match
        assert "metadata" in ofac_match

    def test_ofac_match_confidence_threshold(self):
        """OFAC match with score >= 0.75 should block transaction."""
        result = sanctions_check(
            customer_id="CUST-111222",
            counterparty_details={
                "name": "Company with SANCTIONED word",
                "country": "BY"
            },
            transaction_amount=75000.0
        )

        # Should be blocked based on confidence >= 0.75
        assert result["confidence"] >= 0.75
        assert result["status"] == "blocked"


class TestUNListMatching:
    """Test UN Consolidated List matching."""

    def test_un_match_detection(self):
        """Name containing 'BLOCKED' should trigger UN_CONSOLIDATED match."""
        result = sanctions_check(
            customer_id="CUST-333444",
            counterparty_details={
                "name": "BLOCKED TRADING CORP",
                "country": "CN"
            },
            transaction_amount=150000.0
        )

        assert result["screened"] is True
        assert result["status"] == "blocked", "Exact UN match should block"
        assert result["confidence"] == 1.0, "Exact match should have 1.0 confidence"

        # Check UN match details
        un_match = next(
            (m for m in result["match_list"] if m["list_source"] == "UN_CONSOLIDATED"),
            None
        )
        assert un_match is not None, "Should find UN match in list"
        assert un_match["matched_name"] == "BLOCKED TRADING CORP"
        assert un_match["match_type"] == "exact"
        assert un_match["score"] == 1.0

    def test_multiple_list_matches(self):
        """Entity on both OFAC and UN lists should return both matches."""
        result = sanctions_check(
            customer_id="CUST-555666",
            counterparty_details={
                "name": "SANCTIONED BLOCKED ENTITY",  # Both keywords
                "country": "IR"
            },
            transaction_amount=200000.0
        )

        assert len(result["match_list"]) == 2, "Should match both OFAC and UN"
        assert result["confidence"] == 1.0, "Confidence should be max of all scores"
        assert result["status"] == "blocked"

        list_sources = [m["list_source"] for m in result["match_list"]]
        assert "OFAC_SDN" in list_sources
        assert "UN_CONSOLIDATED" in list_sources


class TestMalformedInputHandling:
    """Test input validation and error handling."""

    def test_invalid_customer_id_empty(self):
        """Empty customer_id should trigger validation error."""
        result = sanctions_check(
            customer_id="",
            counterparty_details={
                "name": "Valid Company",
                "country": "US"
            },
            transaction_amount=10000.0
        )

        assert result["screened"] is False, "Validation failure should set screened=false"
        assert result["status"] == "error"
        assert "error" in result

    def test_invalid_customer_id_special_chars(self):
        """Customer ID with invalid characters should fail validation."""
        result = sanctions_check(
            customer_id="CUST<script>alert('xss')</script>",
            counterparty_details={
                "name": "Valid Company",
                "country": "US"
            },
            transaction_amount=10000.0
        )

        assert result["screened"] is False
        assert result["status"] == "error"

    def test_missing_counterparty_name(self):
        """Missing counterparty name should trigger validation error."""
        result = sanctions_check(
            customer_id="CUST-777888",
            counterparty_details={
                "country": "US"
                # Missing 'name'
            },
            transaction_amount=10000.0
        )

        assert result["screened"] is False
        assert result["status"] == "error"

    def test_invalid_country_code(self):
        """Invalid country code should fail validation."""
        result = sanctions_check(
            customer_id="CUST-999000",
            counterparty_details={
                "name": "Valid Company",
                "country": "USA"  # Should be 2-letter ISO code
            },
            transaction_amount=10000.0
        )

        assert result["screened"] is False
        assert result["status"] == "error"

    def test_negative_transaction_amount(self):
        """Negative transaction amount should fail validation."""
        result = sanctions_check(
            customer_id="CUST-888999",
            counterparty_details={
                "name": "Valid Company",
                "country": "GB"
            },
            transaction_amount=-5000.0
        )

        assert result["screened"] is False
        assert result["status"] == "error"

    def test_zero_transaction_amount(self):
        """Zero transaction amount should fail validation."""
        result = sanctions_check(
            customer_id="CUST-666777",
            counterparty_details={
                "name": "Valid Company",
                "country": "FR"
            },
            transaction_amount=0.0
        )

        assert result["screened"] is False
        assert result["status"] == "error"

    def test_excessive_transaction_amount(self):
        """Transaction amount over limit should fail validation."""
        result = sanctions_check(
            customer_id="CUST-444555",
            counterparty_details={
                "name": "Valid Company",
                "country": "DE"
            },
            transaction_amount=2_000_000_000.0  # Over 1B limit
        )

        assert result["screened"] is False
        assert result["status"] == "error"

    def test_counterparty_name_injection_attempt(self):
        """Counterparty name with injection characters should fail validation."""
        result = sanctions_check(
            customer_id="CUST-222333",
            counterparty_details={
                "name": "Company'; DROP TABLE users;--",
                "country": "CA"
            },
            transaction_amount=10000.0
        )

        assert result["screened"] is False
        assert result["status"] == "error"


class TestPerformanceAssertion:
    """Test performance requirements."""

    def test_response_time_under_200ms(self):
        """Sanctions check should complete in under 200ms."""
        start_time = time.time()

        result = sanctions_check(
            customer_id="CUST-PERF-001",
            counterparty_details={
                "name": "Performance Test Company",
                "country": "JP"
            },
            transaction_amount=30000.0
        )

        end_time = time.time()
        elapsed_ms = (end_time - start_time) * 1000

        assert result["screened"] is True
        assert elapsed_ms < 200, f"Response took {elapsed_ms:.2f}ms, expected < 200ms"
        assert result["processing_time_ms"] < 200, \
            f"Reported processing time {result['processing_time_ms']}ms exceeds 200ms SLA"

    def test_performance_with_match(self):
        """Performance should be acceptable even with matches."""
        start_time = time.time()

        result = sanctions_check(
            customer_id="CUST-PERF-002",
            counterparty_details={
                "name": "SANCTIONED ENTITY FOR PERFORMANCE TEST",
                "country": "KP"
            },
            transaction_amount=50000.0
        )

        end_time = time.time()
        elapsed_ms = (end_time - start_time) * 1000

        assert result["screened"] is True
        assert len(result["match_list"]) > 0, "Should have matches"
        assert elapsed_ms < 200, f"Match detection took {elapsed_ms:.2f}ms, expected < 200ms"

    def test_batch_performance(self):
        """Test multiple consecutive checks maintain performance."""
        elapsed_times = []

        for i in range(10):
            start_time = time.time()

            result = sanctions_check(
                customer_id=f"CUST-BATCH-{i:03d}",
                counterparty_details={
                    "name": f"Batch Test Company {i}",
                    "country": "NL"
                },
                transaction_amount=10000.0 * (i + 1)
            )

            end_time = time.time()
            elapsed_ms = (end_time - start_time) * 1000
            elapsed_times.append(elapsed_ms)

            assert result["screened"] is True

        avg_time = sum(elapsed_times) / len(elapsed_times)
        max_time = max(elapsed_times)

        assert avg_time < 200, f"Average time {avg_time:.2f}ms exceeds 200ms"
        assert max_time < 200, f"Max time {max_time:.2f}ms exceeds 200ms"


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_manual_review_threshold(self):
        """Confidence between 0.50-0.75 should trigger manual review."""
        # This would require a different stub implementation
        # For now, test that the logic exists in the implementation
        pass

    def test_timestamp_format(self):
        """Timestamp should be ISO 8601 format."""
        result = sanctions_check(
            customer_id="CUST-TS-001",
            counterparty_details={
                "name": "Timestamp Test Co",
                "country": "SE"
            },
            transaction_amount=15000.0
        )

        timestamp = result["timestamp"]
        # Should be parseable as ISO 8601
        parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        assert parsed is not None

    def test_reference_id_uniqueness(self):
        """Reference IDs should be unique across calls."""
        result1 = sanctions_check(
            customer_id="CUST-REF-001",
            counterparty_details={"name": "Company A", "country": "IT"},
            transaction_amount=10000.0
        )

        result2 = sanctions_check(
            customer_id="CUST-REF-002",
            counterparty_details={"name": "Company B", "country": "ES"},
            transaction_amount=20000.0
        )

        assert result1["reference_id"] != result2["reference_id"], \
            "Reference IDs should be unique"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
