# 10 · SQL Injection (171 reports · 101 High+Crit)

## What it is
Attacker-controlled input composed into SQL. Error-based, union, boolean/time-blind,
second-order, and NoSQL variants on JSON APIs.

## Attack surface
- Search/filter/`q`/`id`/`label`/`name`/email params, login fields
- sort/order columns, JSON operators (`$ne`, `$gt`, `$where`) on MongoDB-style APIs
- Order/sort params, CSVs imported into DBs ("CSV → SQL")

## Real-world technique language
- "Unauthenticated Error-Based SQL Injection"
- "Blind Boolean-Based SQL Injection … allows unauthenticated database enumeration"
- "Time-based Blind SQLi"
- "Full database Dump with SQLI" (oracle/mssql/mysql fingerprinting)
- "Sql injection Oracle" (error messages expose DB + version)

## Severity drivers
- Data loss/integrity (writes) or full dump → Critical
- Error-based/boolean blind on sensitive tables → High
- Limited garble → Medium

## DeepBug coverage
- `live_rest_validator` baseline-diff battery: error-based on `?q=` / params,
  nested `$ne`/`$in` login payloads, `$where` injection, Mongo/SQL signatures
  (proven: Juice Shop SQLite 500s, VAmPI sqlalchemy)
- GF `sqli` + `nosqli` categories

## Gaps → modules
- **Time-based + boolean-blind probes**: `SLEEP(2)`/`pg_sleep` single-shot,
  boolean-diff on a benign filter (avoid noisy loops; never brute tables without scope OK)
- Second-order SQLi (stored → param) via stored-value reflection
- DB fingerprint extraction from error bodies (map to severity)
