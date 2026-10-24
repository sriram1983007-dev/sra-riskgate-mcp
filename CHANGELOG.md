# Changelog

## 0.6.0 — 2026-10-24
### Added
- `check_transaction` tool: checks the exact transaction an agent is about to sign (`chain_id`,
  `sender`, `to`, `data`, optional `value`), using `sra-riskgate` 0.9.0's `check_transaction`. A plain
  USDC `transfer` is decoded (`decoded.recipient`, `decoded.amount_usdc`) and gets the same checks as
  `check_payment_rules`, including the server's known payees and blocklist, `blocked_addresses` and
  `untrusted_text`. Token approvals (`TOKEN_APPROVAL`, `UNLIMITED_APPROVAL`), other functions, other
  contracts, native ETH and malformed calldata are held. Read-only, offline, fails closed.

### Changed
- Requires `sra-riskgate>=0.9.0`. No change to the other four tools.
- The Dockerfile (used by Glama) installs 0.6.0; it still pinned 0.4.0.

## 0.5.1 — 2026-10-22
### Fixed
- `check_payment_with_model` now sends a `User-Agent: sra-riskgate-mcp/<version>` header. Some proxies in
  front of hosted GPUs refuse Python's default `Python-urllib/3.x` identity with HTTP 403; a vLLM Pod on
  Runpod is one (found while testing the vLLM command from the model card). Before this fix every check
  against such a server was held with `model_unavailable`, so nothing was unsafe, but the model tool could
  not be used there.

## 0.5.0 — 2026-10-21
Counterparty policy from `sra-riskgate` 0.8.0, and MCP tool annotations. Unless you set the new
variables, decisions change only in the two stricter cases listed under "Changed".

### Added
- Known payees: set `SRA_KNOWN_RECIPIENTS` (comma- or space-separated) or `SRA_KNOWN_RECIPIENTS_FILE`
  (one per line). `check_payment_rules` and `check_x402_payment` then **hold** a payment to any other
  recipient (`NEW_COUNTERPARTY`). Known payees come only from server configuration, never from tool
  arguments, so an agent whose input was tampered with cannot mark an attacker's address as known.
- Blocklist: `SRA_BLOCKED_ADDRESSES` / `SRA_BLOCKED_ADDRESSES_FILE`, plus an optional `blocked_addresses`
  argument on both rule tools (it can only add to the list). A payment from or to a listed address is
  **rejected** (`BLOCKLISTED_ADDRESS`).
- Tool annotations on all four tools: read-only, non-destructive, idempotent; `openWorldHint` is true only
  for `check_payment_with_model`.
- `check_address_sanctions` reports the list's age (`sanctions_list.age_days`). Rule results carry the
  SDK's informational `SANCTIONS_LIST_STALE` flag once the bundled list is more than 90 days old.

### Changed
- Sanctions and blocklist matches are checked first. A sanctioned counterparty on an unsupported chain is
  now `reject` (`OFAC_SDN_MATCH`) instead of `hold` (`unsupported_chain`), and in `check_x402_payment` it
  is reported as `OFAC_SDN_MATCH` instead of `unsupported_asset` (still `reject`).
- A malformed or unreadable address list gives `reject` with `configuration_error`; a malformed
  `blocked_addresses` argument gives `reject` with `invalid_arguments`.
- Requires `sra-riskgate>=0.8.0` and `mcp>=1.22`. The old `mcp>=1.2` floor was wrong: releases before
  1.22 fail to import with current pydantic. CI now also tests `mcp==1.22.0`.
- The source distribution includes `tests/conftest.py`.

## 0.4.0
- New tool `check_address_sanctions`: exact, offline match of up to 100 EVM addresses against the OFAC SDN
  snapshot bundled with `sra-riskgate` (124 addresses, as of 2026-10-01). Returns listed / not listed /
  invalid plus the list's source and date. Fails closed: if the list cannot load, nothing is reported as
  "not listed".
- Requires `sra-riskgate>=0.7.1`, so `check_payment_rules` and `check_x402_payment` always **reject**
  payments to or from listed addresses (`OFAC_SDN_MATCH`) and reject USDC amounts below one atomic unit.
  With older SDK versions installed these checks were silently missing.
- Security: `SRA_BASE_URL` must be `http://` or `https://`; any other scheme (for example `file:`) now gives
  `hold` with `configuration_error` instead of being opened.
- Tool descriptions mention the OFAC match.

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
