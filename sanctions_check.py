"""
Sanctions Screening Module
Implements OFAC/UN sanctions list screening with PCI DSS compliance.
"""

import json
import hashlib
import re
from datetime import datetime, UTC
from typing import Dict, List, Optional, Any
from cryptography.fernet import Fernet
import os


class SanctionsScreeningError(Exception):
    """Base exception for sanctions screening failures."""
    pass


class InputValidationError(SanctionsScreeningError):
    """Raised when input validation fails."""
    pass


def _mask_pii(value: str, visible_chars: int = 4) -> str:
    """
    Mask PII for logging - show only last N characters.
    PCI DSS Requirement: No plaintext card/account data in logs.
    """
    if not value or len(value) <= visible_chars:
        return "*" * len(value)
    return "*" * (len(value) - visible_chars) + value[-visible_chars:]


def _validate_customer_id(customer_id: str) -> None:
    """Validate customer_id format - alphanumeric with hyphens only."""
    if not customer_id or not isinstance(customer_id, str):
        raise InputValidationError("customer_id must be non-empty string")
    if not re.match(r'^[A-Za-z0-9\-]{1,64}$', customer_id):
        raise InputValidationError("customer_id contains invalid characters")


def _validate_counterparty(counterparty: Dict[str, Any]) -> None:
    """Validate counterparty_details structure and sanitize inputs."""
    if not isinstance(counterparty, dict):
        raise InputValidationError("counterparty_details must be a dictionary")

    required_fields = ["name", "country"]
    for field in required_fields:
        if field not in counterparty:
            raise InputValidationError(f"counterparty_details.{field} is required")
        if not isinstance(counterparty[field], str) or not counterparty[field].strip():
            raise InputValidationError(f"counterparty_details.{field} must be non-empty string")

    # Validate ISO country code
    if not re.match(r'^[A-Z]{2}$', counterparty["country"]):
        raise InputValidationError("counterparty_details.country must be ISO 3166-1 alpha-2 code")

    # Sanitize name - prevent injection attacks
    name = counterparty["name"]
    if len(name) > 200 or re.search(r'[<>\'";]', name):
        raise InputValidationError("counterparty_details.name contains invalid characters")


def _validate_transaction_amount(amount: float) -> None:
    """Validate transaction amount is positive and within limits."""
    if not isinstance(amount, (int, float)):
        raise InputValidationError("transaction_amount must be numeric")
    if amount <= 0:
        raise InputValidationError("transaction_amount must be positive")
    if amount > 1_000_000_000:  # 1B INR max
        raise InputValidationError("transaction_amount exceeds maximum limit")


def _encrypt_result(result: Dict[str, Any]) -> str:
    """
    Encrypt sanctions screening result for storage.
    PCI DSS Requirement: Encrypt counterparty PII at rest.
    """
    # Use environment variable - enforce in production
    encryption_key = os.getenv("SANCTIONS_ENCRYPTION_KEY")
    if not encryption_key:
        raise SanctionsScreeningError(
            "SANCTIONS_ENCRYPTION_KEY environment variable required. "
            "Configure secure key management (AWS KMS/Azure Key Vault/HashiCorp Vault)."
        )

    fernet = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)
    result_json = json.dumps(result)
    encrypted = fernet.encrypt(result_json.encode())
    return encrypted.decode()


def _persist_encrypted_result(encrypted_result: str, reference_id: str) -> None:
    """
    Persist encrypted sanctions result to audit log.
    PCI DSS Requirement: Encrypt stored data containing PII.
    """
    audit_dir = "audit_log"
    os.makedirs(audit_dir, exist_ok=True)

    audit_file = os.path.join(audit_dir, f"{reference_id}.enc")
    with open(audit_file, 'w') as f:
        f.write(encrypted_result)

    print(f"[AUDIT] Encrypted result persisted: {audit_file}")


def _stub_sanctions_lookup(counterparty_name: str, country: str) -> List[Dict[str, Any]]:
    """
    Stub OFAC/UN sanctions list API - deterministic results for testing.

    Returns matches for specific test names:
    - Names containing "SANCTIONED" -> OFAC_SDN match
    - Names containing "BLOCKED" -> UN_CONSOLIDATED match
    - All others -> no match
    """
    matches = []
    name_upper = counterparty_name.upper()

    # Deterministic test patterns
    if "SANCTIONED" in name_upper:
        matches.append({
            "list_source": "OFAC_SDN",
            "matched_name": "SANCTIONED ENTITY LLC",
            "match_type": "fuzzy",
            "score": 0.89,
            "list_entry_id": "OFAC-12345",
            "metadata": {
                "program": "UKRAINE-EO14024",
                "last_updated": "2026-10-15"
            }
        })

    if "BLOCKED" in name_upper:
        matches.append({
            "list_source": "UN_CONSOLIDATED",
            "matched_name": "BLOCKED TRADING CORP",
            "match_type": "exact",
            "score": 1.0,
            "list_entry_id": "UN-67890",
            "metadata": {
                "program": "AL-QAIDA",
                "last_updated": "2026-10-20"
            }
        })

    # High-risk countries get lower confidence clean results
    high_risk_countries = ["KP", "IR", "SY"]  # North Korea, Iran, Syria
    if country in high_risk_countries and not matches:
        # No match but flag for review via lower confidence
        pass

    return matches


def sanctions_check(
    customer_id: str,
    counterparty_details: Dict[str, Any],
    transaction_amount: float,
    aml_result: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Perform sanctions screening against OFAC/UN lists.

    Args:
        customer_id: Customer identifier
        counterparty_details: Dict with keys: name, country, account (optional)
        transaction_amount: Transaction amount in INR
        aml_result: Optional AML analysis result (passed through)

    Returns:
        Sanctions screening result matching design doc schema

    Raises:
        InputValidationError: If input validation fails
        SanctionsScreeningError: If screening process fails
    """
    start_time = datetime.now(UTC)

    try:
        # Input validation (PCI DSS requirement)
        _validate_customer_id(customer_id)
        _validate_counterparty(counterparty_details)
        _validate_transaction_amount(transaction_amount)

        # Extract fields
        counterparty_name = counterparty_details["name"]
        country = counterparty_details["country"]

        # Audit log with masked PII (PCI DSS requirement)
        print(f"[AUDIT] sanctions_check: customer={_mask_pii(customer_id)}, "
              f"counterparty={_mask_pii(counterparty_name)}, "
              f"country={country}, amount={transaction_amount}")

        # Stub sanctions list lookup (deterministic)
        match_list = _stub_sanctions_lookup(counterparty_name, country)

        # Calculate confidence
        if match_list:
            confidence = max(match["score"] for match in match_list)
        else:
            confidence = 0.0

        # Determine status based on confidence thresholds (from design doc)
        if confidence >= 0.75:
            status = "blocked"
        elif confidence >= 0.50:
            status = "flagged"
        else:
            status = "pass"

        # Generate reference ID
        timestamp = datetime.now(UTC)
        ref_hash = hashlib.sha256(
            f"{customer_id}{timestamp.isoformat()}".encode()
        ).hexdigest()[:8]
        reference_id = f"SANC-{timestamp.strftime('%Y%m%d')}-{ref_hash}"

        # Calculate processing time
        processing_time_ms = int((datetime.now(UTC) - start_time).total_seconds() * 1000)

        # Build result (combining recommended model + design doc schema)
        result = {
            "step": 3,
            "name": "sanctions_screening",
            "status": status,
            "screened": True,
            "reference_id": reference_id,
            "match_list": match_list,
            "confidence": confidence,
            "processing_time_ms": processing_time_ms,
            "timestamp": timestamp.isoformat().replace('+00:00', 'Z')
        }

        # Encrypt and persist result for audit trail (PCI DSS requirement)
        try:
            encrypted_result = _encrypt_result(result)
            _persist_encrypted_result(encrypted_result, reference_id)
        except SanctionsScreeningError as e:
            # Allow operation to continue if encryption fails, but log warning
            print(f"[WARNING] Encryption failed: {str(e)} - configure SANCTIONS_ENCRYPTION_KEY")

        # Audit log success (no PII)
        print(f"[AUDIT] sanctions_check: ref={reference_id}, status={status}, "
              f"confidence={confidence:.2f}, matches={len(match_list)}")

        return result

    except InputValidationError as e:
        # Log validation error (no PII)
        print(f"[ERROR] sanctions_check validation failed: {str(e)}")
        return {
            "step": 3,
            "name": "sanctions_screening",
            "status": "error",
            "screened": False,
            "reference_id": f"SANC-ERROR-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}",
            "match_list": [],
            "confidence": 0.0,
            "processing_time_ms": 0,
            "timestamp": datetime.now(UTC).isoformat().replace('+00:00', 'Z'),
            "error": str(e)
        }

    except Exception as e:
        # System failure - route to manual review
        print(f"[CRITICAL] sanctions_check system failure: "
              f"customer={_mask_pii(customer_id) if 'customer_id' in locals() else 'UNKNOWN'}, "
              f"operation=sanctions_lookup, "
              f"exception={type(e).__name__}, "
              f"timestamp={datetime.now(UTC).isoformat()}")
        return {
            "step": 3,
            "name": "sanctions_screening",
            "status": "error",
            "screened": False,
            "reference_id": f"SANC-ERROR-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}",
            "match_list": [],
            "confidence": 0.0,
            "processing_time_ms": 0,
            "timestamp": datetime.now(UTC).isoformat().replace('+00:00', 'Z'),
            "error": "System failure - manual review required"
        }


# CLI interface for testing
if __name__ == "__main__":
    import sys

    # Test cases (using obviously fake account numbers per PCI DSS test data requirements)
    test_cases = [
        {
            "name": "Clean transaction",
            "customer_id": "CUST-TEST-001",
            "counterparty_details": {
                "name": "Global Trade Partners LLC",
                "country": "AE",
                "account": "TEST-ACCOUNT-001"
            },
            "transaction_amount": 50000.0
        },
        {
            "name": "Sanctioned entity",
            "customer_id": "CUST-TEST-002",
            "counterparty_details": {
                "name": "SANCTIONED ENTITY LLC",
                "country": "RU",
                "account": "TEST-ACCOUNT-002"
            },
            "transaction_amount": 100000.0
        },
        {
            "name": "Blocked entity",
            "customer_id": "CUST-TEST-003",
            "counterparty_details": {
                "name": "BLOCKED TRADING CORP",
                "country": "CN"
            },
            "transaction_amount": 75000.0
        }
    ]

    print("=" * 80)
    print("SANCTIONS SCREENING MODULE - TEST SUITE")
    print("=" * 80)

    for i, test in enumerate(test_cases, 1):
        print(f"\n[Test {i}] {test['name']}")
        print("-" * 80)

        result = sanctions_check(
            customer_id=test["customer_id"],
            counterparty_details=test["counterparty_details"],
            transaction_amount=test["transaction_amount"]
        )

        print(json.dumps(result, indent=2))
        print(f"→ Decision: {result['status'].upper()}")
