# Compliance Controls Matrix

<!-- GENERATED from backend/src/compliance/controlsMatrix.json by scripts/render-compliance.ts — do not edit by hand. -->

Generated: 2026-10-05

This matrix maps every SURF detection rule (R-\*) and platform control (P-\*) to the relevant
obligations under **NIS2 (Directive (EU) 2022/2555)**, **IEC 62443-3-3**, **KRITIS (§8a BSIG)**
and **ISO/IEC 27001:2022 Annex A**.

| Control | Title | NIS2 | IEC 62443-3-3 | KRITIS | ISO 27001 |
|---------|-------|------|---------------|--------|-----------|
| R-01 | Keycloak brute-force login | Art. 21(2)(b) | FR1.1 | §8a BSIG | A.8.5 |
| R-02 | Impossible-travel login for VNB user | Art. 21(2)(b) | FR1.7 | §8a BSIG | A.8.15 |
| R-03 | Successful login after MFA prompt bombing | Art. 21(2)(b) | FR1.7 | §8a BSIG | A.8.5 |
| R-04 | Cross-tenant query | Art. 21(2)(h) | FR5.1 | §8a BSIG | A.8.3 |
| R-05 | JWT signature validation failure spike | Art. 21(2)(b) | FR1.5 | §8a BSIG | A.8.24 |
| R-06 | Command signing service failure spike | Art. 21(2)(e) | FR3.1 | §8a BSIG | A.8.24 |
| R-07 | Unsigned command received at MQTT broker | Art. 21(2)(h) | FR3.1 | §8a BSIG | A.8.16 |
| R-08 | §14a mass-curtailment rate anomaly | Art. 21(2)(e) | FR3.8 | §8a BSIG | A.8.16 |
| R-09 | Safety-setpoint override attempt | Art. 21(2)(e) | FR3.5 | §8a BSIG | A.8.16 |
| R-10 | EMS firmware version rollback | Art. 21(2)(e) | FR3.4 | §8a BSIG | A.8.8 |
| R-11 | Repeated schedule delivery failures to EMS | Art. 21(2)(c) | FR7.1 | §8a BSIG | A.8.14 |
| R-12 | Privileged role grant in Keycloak admin | Art. 21(2)(b) | FR1.3 | §8a BSIG | A.8.2 |
| R-13 | New service account outside change window | Art. 21(2)(b) | FR1.3 | §8a BSIG | A.8.2 |
| R-14 | Kubernetes exec into a production pod | Art. 21(2)(e) | FR2.1 | §8a BSIG | A.8.9 |
| R-15 | DB access from IP outside allow-list | Art. 21(2)(b) | FR1.1 | §8a BSIG | A.8.20 |
| R-16 | HEMS device token brute-force | Art. 21(2)(b) | FR1.1 | §8a BSIG | A.8.5 |
| R-17 | Partner API key failures | Art. 21(2)(b) | FR1.5 | §8a BSIG | A.8.5 |
| R-18 | Keycloak login failures by source IP | Art. 21(2)(b) | FR1.1 | §8a BSIG | A.8.5 |
| R-19 | SSH login from unknown source | Art. 21(2)(b) | FR1.1 | §8a BSIG | A.8.20 |
| R-20 | HEMS device token lifecycle | Art. 21(2)(b) | FR1.3 | §8a BSIG | A.8.15 |
| R-21 | Wazuh high-severity host alert | Art. 21(2)(b) | FR6.2 | §8a BSIG | A.8.16 |
| R-22 | Integrity change in production config or SSH trust | Art. 21(2)(e) | FR3.4 | §8a BSIG | A.8.9 |
| P-01 | OIDC + PKCE + WebAuthn/OTP MFA | Art. 21(2)(j) | FR1.1/FR1.7 | §8a BSIG | A.8.5 |
| P-02 | Tenant-scoped RBAC (surf_tenant_id) | Art. 21(2)(i) | FR2.1 | §8a BSIG | A.8.3 |
| P-03 | Hourly signed Merkle rollups + WORM | Art. 21(2)(h) | FR3.4 | §8a BSIG | A.8.15 |
| P-04 | NIS2 24h/72h/1m report generator | Art. 23 | — | §8b BSIG | A.5.24 |
| P-05 | SOAR safe-mode (dry-run, step-up, four-eyes) | Art. 21(2)(c) | FR2.1 | §8a BSIG | A.5.26 |
| P-06 | Append-only hash-chained audit_actions | Art. 21(2)(h) | FR3.4 | §8a BSIG | A.8.15 |
| P-07 | TLS 1.3 + HSTS + CSP edge hardening | Art. 21(2)(h) | FR4.1 | §8a BSIG | A.8.24 |
| P-08 | GDPR Art. 15/17 data-subject workflows | — | — | — | A.5.34 |

## Notes

- **NIS2 Art. 21(2)** enumerates the risk-management measures; the letter in parentheses
  identifies the specific measure (e.g. (b) = incident handling, (h) = cryptography).
- **NIS2 Art. 23** governs incident reporting (24h early warning / 72h notification / 1-month
  final report) — implemented by the NIS2 report generator (control P-04).
- **IEC 62443-3-3 FR** = Foundational Requirement (FR1 Identification & Authentication,
  FR2 Use Control, FR3 System Integrity, FR4 Data Confidentiality, FR5 Restricted Data Flow,
  FR7 Resource Availability).
- Cryptographic auditability (P-03, P-06) provides the tamper-evidence required for
  KRITIS evidence retention and NIS2 Art. 21(2)(h).
