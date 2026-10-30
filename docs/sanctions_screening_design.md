# Sanctions Screening — Design Document

**Author:** Claude Code  
**Date:** 2026-10-30  
**Status:** Draft  
**Target Release:** Phase 2 Compliance Enhancement

---

## 1. Pipeline Position

### Current Pipeline
```
kyc_check (step 1) → aml_analysis (step 2) → approval (step 3)
```

### Proposed Pipeline
```
kyc_check (step 1) → aml_analysis (step 2) → sanctions_screening (step 3) → approval (step 4)
```

### Rationale

Sanctions screening is inserted **after AML analysis** and **before approval** for the following reasons:

1. **After AML**: AML behavioral analysis provides context for sanctions risk scoring. Transaction patterns flagged by AML (e.g., structuring, geographic anomalies) can indicate attempts to obscure sanctioned entity involvement.

2. **Before Approval**: Sanctions screening is a **binary gate** with strict liability. OFAC regulations require blocking sanctioned transactions before authorization. This "fail-fast" approach prevents resource waste on approval workflows for blocked entities.

3. **PCI DSS Alignment**: Separating sanctions from approval maintains clear audit trails per PCI DSS 10.2 (transaction logging requirements).

---

## 2. Data Inputs Required

| Field | Type | Source | Required | Notes |
|-------|------|--------|----------|-------|
| `customer_id` | string | Transaction payload | Yes | Primary account holder identifier |
| `counterparty_details` | object | Transaction payload | Yes | See schema below |
| `transaction_amount` | float | Transaction payload | Yes | Used for risk-weighting and threshold triggers (USD equivalent) |
| `aml_result` | object | AML module output | Yes | Passed through for context; see integration contract |

### counterparty_details Schema
```json
{
  "name": "string",           // Full legal name or business entity
  "country": "string",        // ISO 3166-1 alpha-2 code
  "account": "string",        // Optional: IBAN or local account number
  "additional_info": "object" // Optional: beneficial owners, aliases
}
```

---

## 3. Output Schema

```json
{
  "screened": true,
  "match_list": [
    {
      "list_source": "OFAC_SDN",
      "matched_name": "Example Sanctioned Entity",
      "match_type": "exact|fuzzy",
      "score": 0.92,
      "list_entry_id": "12345",
      "metadata": {
        "program": "UKRAINE-EO14024",
        "last_updated": "2026-10-15"
      }
    }
  ],
  "confidence": 0.92,
  "processing_time_ms": 145,
  "timestamp": "2026-10-30T12:34:56Z"
}
```

### Field Definitions

- **`screened`** (bool): Whether the screening step executed successfully. `false` indicates system failure requiring manual review.
- **`match_list`** (array): Zero or more sanctions list matches. Empty array means no matches found.
  - **`list_source`**: Sanctions list identifier (OFAC_SDN, UN_CONSOLIDATED, EU_SANCTIONS, etc.)
  - **`matched_name`**: Name from the sanctions list that triggered the match
  - **`match_type`**: `exact` for direct matches, `fuzzy` for algorithmic matches above threshold
  - **`score`**: Match confidence (0.0–1.0), where 1.0 is exact match
  - **`list_entry_id`**: Reference ID in the source sanctions list
  - **`metadata`**: Additional context (sanctions program, list update date)
- **`confidence`** (float): Overall confidence in the screening result (0.0–1.0). For multiple matches, reflects highest score.
- **`processing_time_ms`** (int): Screening latency for performance monitoring
- **`timestamp`** (string): ISO 8601 timestamp of screening execution

---

## 4. Integration Contract with the AML Module

### Input from AML Module

The sanctions screening step receives:

```json
{
  "aml_result": {
    "status": "pass|flagged|fail",
    "risk_score": 0.45,
    "flags": ["high_velocity", "geographic_anomaly"],
    "analyst_notes": "Optional context from AML review"
  }
}
```

**Key Points:**
- AML result passes through **unchanged** to approval step
- Sanctions screening runs **independently** of AML verdict
- AML flags inform sanctions risk weighting but do not override match logic

### Output to Approval Step

The approval step receives:

```json
{
  "kyc_check": { /* step 1 output */ },
  "aml_analysis": { /* step 2 output */ },
  "sanctions_screening": { /* step 3 output from schema above */ }
}
```

**Decision Logic:**
- **Hard Stop**: Any non-empty `match_list` with `confidence >= 0.75` → Block transaction, route to manual compliance review
- **Manual Review**: `0.50 <= confidence < 0.75` → Flag for analyst review before approval
- **Pass**: Empty `match_list` OR `confidence < 0.50` → Continue to approval
- **System Failure**: `screened: false` → Route to manual review (never silently pass)

### Failure Mode Handling

| Scenario | `screened` | Action |
|----------|-----------|--------|
| Sanctions API unreachable | `false` | Route to manual review, log critical error |
| Timeout (>5s) | `false` | Route to manual review, alert infrastructure team |
| Malformed input | `false` | Reject transaction, return 400 error to client |
| Empty/stale sanctions list | `false` | Block all transactions, alert compliance team |

**PCI DSS Requirement:** All failure modes must generate audit log entries per CLAUDE.md section 4.

---

## 5. Open Questions / Risks

### Phase 1 Discussion Items

1. **False Positive Rate**: What is the acceptable false positive rate for fuzzy matching? Industry standard is ~2-5%.

2. **Name Matching Algorithm**: Which fuzzy matching algorithm (Levenshtein, Jaro-Winkler, phonetic)? Recommend Jaro-Winkler with threshold 0.85.

3. **List Refresh Cadence**: How frequently are sanctions lists updated? OFAC updates daily; recommend 4-hour refresh cycle.

4. **Performance SLA**: Target p95 latency? Current estimate 150ms; need to validate against banking-api MCP server capabilities.

5. **Multi-Language Support**: Do we need to screen non-Latin alphabets (Cyrillic, Arabic)? May require transliteration service.

6. **Beneficial Owner Screening**: Should we recursively screen beneficial owners in `counterparty_details.additional_info`?

### Risks & Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Sanctions list API downtime | High (regulatory violation) | Low | Implement local list cache with 24h TTL, manual review fallback |
| False negatives (missed match) | Critical (OFAC penalties) | Low | Dual-vendor screening, quarterly audit of match logic |
| Performance degradation | Medium (UX impact) | Medium | Parallel API calls, circuit breaker pattern, 5s timeout |
| Data privacy (counterparty PII) | High (PCI DSS violation) | Low | Encrypt counterparty details at rest, mask in logs |

---

## 6. Implementation Phases

### Phase 1: MCP Tool Integration (Week 1-2)
- [ ] Add `sanctions_screening` tool to banking-api MCP server
- [ ] Implement output schema validation
- [ ] Add audit logging per PCI DSS requirements

### Phase 2: Pipeline Integration (Week 3)
- [ ] Update `get_compliance_pipeline` to return 4-step sequence
- [ ] Modify transaction flow to call sanctions screening between AML and approval
- [ ] Implement failure mode routing

### Phase 3: Testing & Validation (Week 4)
- [ ] Unit tests with OFAC test data sets
- [ ] Integration tests with full pipeline
- [ ] Performance benchmarking (target p95 < 200ms)
- [ ] False positive/negative analysis

### Phase 4: Production Rollout (Week 5)
- [ ] Dark launch (screen but don't block)
- [ ] Monitor false positive rate for 3 days
- [ ] Enable blocking logic
- [ ] Document runbook for compliance team

---

## 7. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Screening latency (p95) | < 200ms | APM traces |
| False positive rate | < 3% | Manual review queue analysis |
| False negative rate | 0% | Quarterly OFAC test case validation |
| Availability | 99.9% | Uptime monitoring |
| Audit compliance | 100% | PCI DSS audit review |

---

## Appendix A: Sample Transaction Flow

```json
// Input to sanctions_screening step
{
  "customer_id": "CUST-789012",
  "counterparty_details": {
    "name": "Global Trade Partners LLC",
    "country": "AE",
    "account": "AE070331234567890123456"
  },
  "transaction_amount": 50000.00,
  "aml_result": {
    "status": "pass",
    "risk_score": 0.25,
    "flags": []
  }
}

// Output from sanctions_screening step
{
  "screened": true,
  "match_list": [],
  "confidence": 0.0,
  "processing_time_ms": 142,
  "timestamp": "2026-10-30T12:34:56Z"
}
```

---

## Appendix B: Regulatory References

- **OFAC Sanctions Compliance**: 31 CFR Chapter V
- **PCI DSS 4.0**: Requirements 10.2 (audit logging), 10.3 (audit trail integrity)
- **FinCEN Customer Due Diligence**: 31 CFR 1010.230
- **Bank Secrecy Act**: 31 USC 5318(h) (AML program requirements)
