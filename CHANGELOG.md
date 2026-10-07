# Changelog

## 0.1.0
- First release: `check_payment_rules`, `check_x402_payment` and `check_payment_with_model` tools.
- Model calls use SRA-RiskGate-4B's exact training prompt; every failure path returns `hold`.
- Works with MCP Python SDK 1.x and 2.x.
