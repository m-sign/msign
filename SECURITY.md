# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.x (latest minor) | Yes |
| 0.x | No |

## Reporting a vulnerability

Do not open a public issue. Report privately, by either of these:

- GitHub private vulnerability reporting: the "Report a vulnerability" button on this repository's Security tab.
- Email: `as[.]m[.]github-report[@]melnyk[.]org` (replace `[.]` with `.` and `[@]` with `@`).

Please include:

- the module version (`go list -m github.com/m-sign/msign`) and Go version;
- a description of the issue and its impact;
- steps or code to reproduce it.

Do not include real private keys in a report.

We aim to acknowledge reports within 7 days. We will agree on a disclosure date with you, publish a GitHub security advisory with the fix, and credit you unless you prefer otherwise.

Issues in the format specification itself belong to [m-sign/specs](https://github.com/m-sign/specs/security).
