# Security Policy

## Scope

VulnMap is an early-stage defensive security project.

## Reporting a Vulnerability

Please do not publish exploitable details of an unpatched vulnerability
in a public issue.

Use GitHub's private vulnerability reporting feature if it is enabled
for this repository. Otherwise, contact the maintainers privately.

Include the affected version, impact, reproduction steps, and any
available mitigation.

## Security Principles

- Never expose secrets in logs or public reports.
- Treat imported vulnerability data as untrusted input.
- Do not execute untrusted repository code on the API server.
- Require authorization before accessing private project data.
- Verify proposed remediation before marking an issue resolved.

This project is not yet intended for production security monitoring.