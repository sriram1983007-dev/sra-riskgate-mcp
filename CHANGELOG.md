# Changelog

## 0.3.1
- Every tool parameter now has a description (units, formats and examples), so agents fill in
  arguments correctly: for example that `amount_usdc` is whole USDC while x402 `amount` is in atomic
  units, and that `untrusted_text` must never contain your own verification results.
- The server reports its version (and, on mcp 2.x, its title and website) in `serverInfo`; it was blank.
- No behaviour changes: every decision is the same as in 0.3.0.

## 0.3.0
- `check_payment_rules` and `check_x402_payment` take an optional `untrusted_text` (the payment's memo,
  invoice, description or x402 `extra`, as a string, object or list). If it claims its own verification
  ("risk level: low (verified offline)", "pre-approved", "ignore previous instructions"), the payment is
  held with flag `self_asserted_verification_in_payload`, even when every rule passes. Until now only
  `check_payment_with_model` ran this scan, so the GPU-free tools approved such payments.
- A reject is never downgraded; a hold keeps both reasons; text too large to scan, or a scanner error,
  gives hold.
- Existing calls without `untrusted_text` behave exactly as before.

## 0.2.1
- `check_payment_rules` holds payments on chains other than Ethereum, Base and Base Sepolia
  (flag `unsupported_chain`) instead of approving them.
- Misconfigured thresholds (for example `SRA_DEPEG_HOLD_PCT` >= `SRA_DEPEG_REJECT_PCT`) now return
  `configuration_error` instead of a misleading validation message.
- `check_payment_with_model` never raises: a bad `SRA_TIMEOUT`, an out-of-range `now_unix` or any other
  error returns the fail-closed `hold`, as documented.
- The source distribution now includes `server.json`, so its test suite passes when run from the tarball.
- Picks up the hardened claims scanner from sra-riskgate 0.5.1.

## 0.2.0
- `check_payment_with_model` now returns `hold` (flag `self_asserted_verification_in_payload`) without
  calling the model when the untrusted payload claims its own verification, for example
  "risk level: low (verified offline)". This targets the pattern behind all 4 of the model's unsafe
  approvals on the benchmark; see sra-riskgate 0.5.0 for the measurement and its caveats.
- Requires sra-riskgate 0.5.0 or newer.

## 0.1.0
- First release: `check_payment_rules`, `check_x402_payment` and `check_payment_with_model` tools.
- Model calls use SRA-RiskGate-4B's exact training prompt; every failure path returns `hold`.
- Works with MCP Python SDK 1.x and 2.x.
