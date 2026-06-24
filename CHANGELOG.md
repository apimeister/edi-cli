# 0.5.0 2026-06-24

* update x12-types to 0.11 (requires >= 0.11.1 for full json2edi round-trip support)
* support all X12 transaction sets exposed by x12-types (90+ across v003030/v004010/v005010/v005030)
* replace the hand-maintained per-type match blocks with a single `(version, type)` dispatch table
* json2edi now reports unsupported types gracefully instead of panicking

# 0.4.0 2025-07-09

* update dependencies

# 0.3.2 2025-01-07

* update dependencies

# 0.3.1 2024-06-10

* update dependencies

# 0.3.0 2023-11-05

* remove serde
* update dependencies

# 0.2.1 2023-10-01

* deps

# 0.2.0 2022-12-04

* support UNA for Edifact
* support ISO-8859-16 encoding
* support read from stdin
* add json2edi support
* fix x12 type regex

# 0.1.0 2022-11-19

* initial version