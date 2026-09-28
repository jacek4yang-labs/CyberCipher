# Security Policy

## Reporting

CyberCipher is an offline desktop tool. If you find a vulnerability —
especially anything that could exfiltrate user data, execute unintended code
from recipe files, or crash the engine via malformed input — please open a
GitHub security advisory ("Report a vulnerability") rather than a public
issue.

## Scope notes

- The engine never sends data to remote services; there is no network code in
  the core crates. Any PR introducing network I/O must justify it in review.
- Recipe files are data, not code: importing a recipe must never execute
  anything beyond the fixed operation registry.
- External tool adapters (planned) always run through explicit, user-configured
  paths with timeouts and argument lists — never shell-concatenated input.

## Supported versions

Pre-1.0: only the latest commit on `main` is supported.
