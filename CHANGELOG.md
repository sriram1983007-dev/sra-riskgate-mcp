# Changelog

## 0.14.0 — 2026-11-10

- New settings `SRA_EXTRA_TOKENS` and `SRA_EXTRA_TOKENS_FILE`: US-dollar stablecoins the SDK does not list,
  as JSON (`symbol`, `chain_id`, `contract`, `decimals`, optional `eip3009`). Registered with sra-riskgate
  1.1.0's `register_stablecoin()`, so every tool recognises them: the payment checks (once enabled with
  `SRA_ALLOWED_TOKENS`), `verify_settlement(token=...)` and `check_allowances(token=...)`.
- Fails closed: malformed JSON, an unknown key, an unreadable file, or an entry that would change a built-in
  token is a configuration error in every tool that reads it.
- Requires `sra-riskgate>=1.1.0`.

## 0.13.0 — 2026-11-06

- USDT, USDB (Bridge) and USDG in the checks before signing, from sra-riskgate 1.0.0. New server setting
  `SRA_ALLOWED_TOKENS` (default `USDC`): the stablecoins `check_payment_rules`, `check_transaction`,
  `check_x402_authorization`, `check_circle_wallets_request` and `check_user_operation` may approve. A token not
  enabled is held as `UNSUPPORTED_ASSET`; an unknown symbol is a configuration error. Enabling is a server
  setting only, never a tool argument.
- `check_payment_rules` takes optional `token` ("USDC", "USDT", "USDB", "USDG"); `amount_usdc` is then in whole
  tokens of that coin. Robinhood Chain (4663) is accepted for USDG.
- `check_transaction` reads the token from the contract called; `decoded` now also has `token` and `amount`
  (`amount_usdc` is kept for USDC).
- A `TransferWithAuthorization` for USDT, USDB or USDG is held (`UNSUPPORTED_SIGNATURE`): read on chain, none of
  them implements EIP-3009, so it could never settle. Approvals and permits are held for every token.
- UserOperations sum payments to one payee across tokens (`BATCH_TOTAL`).
- `check_x402_payment` and `verify_gateway_balances` stay USDC-only. Requires `sra-riskgate>=1.0.0`.

## 0.12.0 — 2026-11-06

- `verify_settlement` takes optional `token`, `decimals` and `symbol`: a named stablecoin ("USDT", "USDB", "USDG",
  "USDC") with its contract and decimals filled in for the chain, or any ERC-20 contract address with its
  decimals. Without them it checks USDC as before. Closes Audit #13 Finding 2: USDG, USDT and USDB settlements were
  verifiable in the Python SDK since 0.19.0 / 0.20.0 but not through MCP.
- New tool `check_allowances`: standing approvals behind pull payments. Holds unlimited allowances, allowances
  above `SRA_MAX_ALLOWANCE` and allowances to spenders outside `SRA_EXPECTED_SPENDERS` (+ `_FILE`); rejects
  sanctioned or blocked spenders. The expected spenders and the limit come only from server settings.
- `verify_gateway_balances` stays USDC-only: Circle Gateway holds USDC.
- Requires `sra-riskgate>=0.20.0`. Tool count: 12.

## 0.11.1 — 2026-11-04

- The source distribution now includes the test data (`tests/data/*.json`), so the published test suite runs
  from the sdist. 0.10.0 and 0.11.0 shipped without `smart_account_calldata.json` and their sdist tests fail at
  collection; the server code is unchanged. Found in Audit #12.
- A packaging test checks that every file under `tests/` is covered by `MANIFEST.in`.

## 0.11.0 — 2026-11-04

- New tool `verify_settlement`: after a payment settles, checks the mined receipt holds exactly the approved USDC
  payment (one Transfer from payer to payee for the approved amount, and with `authorization_nonce` the approved
  x402 authorization's AuthorizationUsed event). Returns `verified` and a flag when not: `SETTLEMENT_FAILED`,
  `SETTLEMENT_NOT_FOUND`, `SETTLEMENT_AMOUNT_MISMATCH`, `SETTLEMENT_PAYEE_MISMATCH`, `DUPLICATE_SETTLEMENT`,
  `UNEXPECTED_TRANSFER`, `AUTHORIZATION_NOT_USED`, `INVALID_RECEIPT`.
- New tool `verify_gateway_balances`: a Circle Gateway payment, from Gateway balances read before and after.
- `check_x402_payment` takes `max_timeout_seconds` (and `extra`): a requirement asking for a signature valid longer
  than `SRA_MAX_AUTH_VALIDITY_SECONDS` (default one hour) is held as `LONG_TIMEOUT_REQUESTED`; Circle Gateway
  requirements for Circle's GatewayWallet get `SRA_MAX_GATEWAY_VALIDITY_SECONDS`. Suggested by Carlos (Bloqarl).
- Requires `sra-riskgate>=0.18.0`.

## 0.10.0 — 2026-11-01

- New tool `check_user_operation`: checks an ERC-4337 UserOperation from a smart account (Coinbase Smart Wallet,
  CDP smart accounts, Safe, Kernel, Nexus, SimpleAccount) before it is signed. Every call in the operation is
  decoded and checked like `check_transaction`, payments to the same payee are summed (`BATCH_TOTAL`), and
  self-calls, delegatecalls, unreadable callData, in-operation deployment, EIP-7702 authorizations and
  unexpected paymasters are held. Returns the decoded calls.
- New settings: `SRA_EXPECTED_PAYMASTERS` (and `_FILE`) and `SRA_ALLOW_ACCOUNT_DEPLOYMENT`.
- Requires `sra-riskgate>=0.17.0`.

## 0.9.2 — 2026-10-29

- Every payment tool (`check_payment_rules`, `check_x402_payment`, `check_transaction`, `check_x402_authorization`,
  `check_circle_wallets_request`) takes an optional `account_code`, the wallet's `eth_getCode` result. If the
  wallet is delegated under EIP-7702 to a contract not in the new `SRA_EXPECTED_DELEGATES` setting, the payment is
  held as `ACCOUNT_DELEGATED`. Suggested by Carlos (Bloqarl) on DEV.to.
- Requires `sra-riskgate>=0.16.0`.

## 0.9.1 — 2026-10-27

- `check_delegation`: checks a standalone EIP-7702 authorization before the agent signs it (always held as
  `CODE_DELEGATION`, naming the delegate contract and whether chain id 0 makes it valid on every chain).
  Transactions carrying an `authorizationList` were already held by `check_transaction`.
- `server.json` now declares every setting the server reads, including `SRA_MAX_GATEWAY_VALIDITY_SECONDS`,
  `SRA_CIRCLE_WALLETS` and `SRA_CIRCLE_USDC_TOKEN_IDS`, so MCP clients can offer them; `SRA_API_KEY` is marked
  secret. A test keeps the list in step with the code.

## 0.9.0 — 2026-10-27

### Added
- `check_circle_wallets_request`: checks a Circle Wallets (developer-controlled) API request before the agent
  sends it, using `sra-riskgate` 0.14.0. Transfers (USDC, native USDC on Arc), contract executions (rebuilt into
  calldata; `approve()` held), `signTypedData` (x402, Gateway, Permit) and `signTransaction` (including EIP-7702);
  `signMessage` and wallet upgrades are held. New settings `SRA_CIRCLE_WALLETS` and `SRA_CIRCLE_USDC_TOKEN_IDS`.

### Fixed
- **0.8.0 held payments made by Circle's own Gateway SDK.** `@circle-fin/x402-batching` signs Gateway
  authorizations for 7 days plus 100 seconds, just over 0.8.0's 7-day default. The default
  `SRA_MAX_GATEWAY_VALIDITY_SECONDS` is now 8 days.
- Requires `sra-riskgate>=0.14.0`.

## 0.8.0 — 2026-10-26

- `check_x402_authorization` supports Circle Gateway batched payments (nanopayments), using `sra-riskgate` 0.13.0:
  a `TransferWithAuthorization` signed for the `GatewayWalletBatched` domain with Circle's GatewayWallet contract
  is checked like any x402 payment instead of being held as long-lived. Gateway requires these to stay valid for at
  least 3 days, so they have their own server-side limit, `SRA_MAX_GATEWAY_VALIDITY_SECONDS` (default 7 days).
  The decoded result includes `"via": "circle_gateway"`.
- Requires `sra-riskgate>=0.13.0`.

## 0.7.2 — 2026-10-25

- `check_transaction` takes optional `tx_type` and `authorization_list`, so an EIP-7702 code delegation
  (a type 4 transaction, or any authorization) is held as `CODE_DELEGATION`. Before, the tool had no way to
  see a delegation. Thanks to Carlos (Bloqarl) on DEV.to for the question that found this.
- Requires `sra-riskgate>=0.12.1`.

## 0.7.1 — 2026-10-25

- Arc (Circle's blockchain), mainnet `5042` and testnet `5042002`, in every tool, using `sra-riskgate` 0.12.0.
  On Arc, USDC is the native asset: `check_transaction` checks a plain native send (value in 18-decimal units,
  `data` "0x") as a USDC payment and returns its decoded recipient and amount; native value sent with a contract
  call is held. Tool and parameter descriptions name the supported chains.
- Requires `sra-riskgate>=0.12.0`.

## 0.7.0 — 2026-10-25

- `check_x402_authorization` tool: checks the EIP-712 typed data an agent signs for an x402 payment
  (EIP-3009 `TransferWithAuthorization`) before it signs, using `sra-riskgate` 0.11.0's
  `check_authorization`. A current, short-lived USDC authorization is decoded (the result includes the
  recipient, amount and expiry) and gets every check of `check_payment_rules`. Expired, post-dated and
  long-lived authorizations, permits, non-USDC domains, other primary types and a `from` that is not the
  agent's wallet are held. The time is the server's clock, never a tool argument.
- New setting `SRA_MAX_AUTH_VALIDITY_SECONDS` (default 3600).
- Requires `sra-riskgate>=0.11.0`. No change to the other five tools.

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
