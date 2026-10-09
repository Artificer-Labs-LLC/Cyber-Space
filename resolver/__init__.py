"""cybernet-resolver: the local DNS face of .cyberspace.

A small authoritative DNS server for the .cyberspace zone and nothing else —
split-horizon by construction. <label>.cyberspace queries run the six-step
fail-closed resolve_cyberspace() from core.py; any failure answers NXDOMAIN.
Everything outside .cyberspace is forwarded to the upstream resolver
untouched.

Decision (build tick 2026-10-07): the DNS codec is hand-rolled in stdlib
(see resolver/dns.py), not dnslib. The design note permits it, dnslib is not
in the project venv, and a dependency-free daemon installs anywhere. The
codec is deliberately minimal: it parses only what the daemon answers
(standard queries, one question, A/AAAA type) and builds only what the
daemon returns (A records, NXDOMAIN, SERVFAIL). Anything malformed gets
SERVFAIL — never a guess.
"""
