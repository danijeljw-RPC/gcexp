# gcexp — GNU Certificate Expiry Checker

`gcexp` is a cross-platform, automation-friendly CLI that checks local GnuPG keys, X.509/PEM certificates, PKCS#12 bundles, ordinary SSH keys, and OpenSSH certificates for expiry. Scans are read-only and one bad input does not stop other checks.

## Build and test

Requires the .NET 10 SDK.

```bash
dotnet restore
dotnet build gcexp.slnx -c Release
dotnet test gcexp.slnx -c Release
dotnet publish src/gcexp.csproj -c Release -r win-x64
dotnet publish src/gcexp.csproj -c Release -r linux-x64
```

Native AOT publishing requires the native toolchain for the target OS; cross-OS AOT is unsupported. CI publishes Windows on Windows and Linux on Linux.

## Usage

```bash
gcexp --help
gcexp --version
gcexp scan --gpg
gcexp scan --gpg --warn-days 60
gcexp scan --gpg-home ~/.gnupg
gcexp scan --file ./certificate.pem
gcexp check ./certificate.pem
gcexp scan --path ./certificates --recursive
gcexp scan --path ./certificates --warn-days 90 --json
gcexp scan --file C:\certificates\service.pfx --pfx-password-env GCEXP_PFX_PASSWORD
```

`--file` and `--path` may repeat. With no locations, `scan` returns an empty successful report. `--all` checks GPG and supported files in the current directory only; it is deliberately non-recursive. Supported extensions are `.cer`, `.crt`, `.der`, `.pem`, `.pfx`, `.p12`, and `.pub`. PEM files may contain multiple certificates. A PKCS#12 bundle may contain multiple certificates.

GPG checks require `gpg` or `gpg2` on `PATH` and use colon-format output. OpenSSH certificate inspection requires `ssh-keygen`; ordinary `.pub` keys are reported as `NoExpiry` because they contain no embedded expiry. File content, not the `.pub` suffix alone, identifies OpenSSH certificates.

PFX passwords never appear in command arguments or output. Put the password in an environment variable and pass only its name with `--pfx-password-env`. Unset means an unprotected bundle. Clear the variable after use.

JSON uses stable camel-case properties, UTC ISO-8601 dates, string statuses, `null` for no expiry, and a separate errors array. Days remaining are UTC calendar-day differences: an expiry later today is 0; an already-passed instant today is expired with 0 days.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | No expiring/expired results or inspection errors |
| 1 | At least one result is within the warning threshold |
| 2 | At least one result is expired |
| 3 | At least one inspection error occurred |
| 64 | Invalid command-line usage |

Precedence is error, expired, expiring, OK. JSON mode returns the same monitoring code.

## Security and limitations

The tool never exports or prints private key material and does not modify certificates or keyrings. Paths remain present in results because operators need source attribution; JSON should therefore be handled as operational data. Filesystem traversal does not follow directories by default, and recursive enumeration reports traversal failures but may not enumerate accessible descendants beneath an inaccessible directory. Password prompting is intentionally omitted to keep non-interactive behavior deterministic; environment variables are the supported secret channel. Remote TLS endpoints, system certificate stores, Java keystores, cloud managers, and renewal are out of scope.
