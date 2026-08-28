"""
ProbeX Engine – detectors sub-package.

Each detector module in this package implements a single vulnerability class.
Detectors are pure functions that accept a (payload, response) pair and return
a Finding or None.

Example detectors to implement (future tasks):
  - xss.py          – Reflected / Stored XSS
  - sqli.py         – SQL Injection (error-based, blind-time)
  - open_redirect.py – Open Redirect
  - headers.py      – Missing Security Headers
  - ssrf.py         – Server-Side Request Forgery

Zero FastAPI / SQLModel imports — this package must stay standalone.
"""
