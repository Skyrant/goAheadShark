# Security Advisory Report — Three TLS Vulnerabilities in the GoAhead Embedded Web Server

**Classification:** Business / Executive Briefing
**Date:** 28 October 2026
**Prepared from public disclosures by:** FoxIO (Sébastien Féry) and the EmbedThis GoAhead security advisories
**Affected product:** GoAhead Embedded Web Server (TLS/SSL subsystem)

---

## 1. Executive Summary

GoAhead is one of the most widely deployed embedded web servers in the world. It provides the
device-management and administration web interface built into **hundreds of millions** of IoT,
networking, operational-technology (OT), and defense devices — including products from Palo Alto
Networks, Comcast, D-Link, HP, Canon, Honeywell, GE, Oracle, Siemens, Rockwell, Digi, Lockheed
Martin, and Boeing.

Three independent flaws were discovered in how GoAhead integrates with its underlying TLS
(encryption) libraries. Each flaw weakens a different security guarantee that customers rely on to
trust the device management channel:

| ID | Weakness | Severity (CVSS) | Business impact in one line |
|----|----------|-----------------|------------------------------|
| **GOAHEAD-SA-2026-0006** (CVE-2026-115881) | Certificate revocation silently not enforced | **Critical — 9.1** | A certificate you *revoked* (e.g. a stolen device) still gets in. |
| **GOAHEAD-SA-2026-0004** (CVE-2026-115884) | Client-certificate chain-depth check bypass | **High — 7.4** | An attacker with no valid credentials can authenticate. |
| **GOAHEAD-SA-2026-0005** | Encryption key (DH parameter) truncation | **Medium — 5.9** | Some encrypted admin sessions can be passively decrypted. |

**All three are fixed in GoAhead 6.1.1 (released 2 August 2026). The primary recommendation is to
upgrade every GoAhead-based device to 6.1.1 or later.**

Importantly, **which flaws apply to a given device depends on how that device's firmware was built**
(which TLS library it was compiled against and how mutual-TLS is configured). No single device is
exposed to all three in the same configuration, but a large, mixed fleet is almost certainly exposed
to at least one.

---

## 2. Why This Matters to the Business

GoAhead almost never faces the public internet as a "website." Instead it is the **management
plane** of a device — the HTTPS interface an administrator (or an automated system) uses to
configure a router, firewall, printer, gateway, or industrial controller. Compromising that plane
typically means **full administrative control of the device**, which in turn can mean:

- Network pivot and lateral movement (firewalls, routers, gateways).
- Disruption or sabotage of physical processes (OT / industrial controllers).
- Theft of credentials and configuration.
- Persistence that survives reboots and is hard to detect.

Because these devices are long-lived, rarely patched, and often deployed in the thousands, a TLS
authentication or confidentiality weakness has an unusually long and wide blast radius.

---

## 3. The Three Vulnerabilities (Plain-Language)

### 3.1 Critical — Revoked certificates are silently accepted (SA-2026-0006 / CVE-2026-115881)

**What it is.** Security-conscious operators enable *mutual TLS* — the device demands a client
certificate before granting access — and configure a **Certificate Revocation List (CRL)** so that
compromised or decommissioned device certificates can be invalidated. GoAhead loads the CRL but, due
to a missing one-line instruction, never actually *checks* it. The revocation list is read and then
ignored on every connection.

**Why it is serious.** The operator did everything right and received no error or warning — the
device reports success at start-up — yet revocation is completely non-functional. A stolen,
retired, or otherwise compromised certificate that the operator *believes* they have revoked will
continue to be accepted indefinitely. This is a silent failure of a control specifically deployed to
contain a breach, which is why it carries a **Critical 9.1** rating.

**Who is affected.** Devices built with the **OpenSSL-compatible backend** (the default), running
GoAhead **3.4.5 through 6.1.0**, with mutual TLS *and* a CRL configured. These are exactly the most
security-mature deployments — the operators who bothered to configure revocation are the ones
exposed.

### 3.2 High — Authentication bypass via over-long certificate chain (SA-2026-0004 / CVE-2026-115884)

**What it is.** When a device requires client certificates but is configured not to verify the
*issuer* (the trusted authority that signed the certificate), GoAhead is supposed to still reject
certificate chains that are suspiciously long. On devices built against certain **LibreSSL** library
versions, that length check is skipped because of how verification errors are handled. An attacker
can present a long, entirely self-made ("self-signed") certificate chain and complete the handshake
as an *authenticated* client — **without possessing any legitimate credential**.

**Why it is serious.** It converts a mutual-TLS gate — intended to be a strong barrier — into one
that an unauthenticated attacker can walk through, provided they can reach the endpoint. Rated
**High 7.4**.

**Who is affected.** Devices built against **LibreSSL 3.2.x or 3.3.2–3.3.6**, GoAhead **≤ 6.1.0**,
configured with client-certificate verification on but issuer checking off. Builds using OpenSSL,
BoringSSL, AWS-LC, or LibreSSL 4.x are **not** exposed to this trigger.

### 3.3 Medium — Weak encryption keys make sessions decryptable (SA-2026-0005)

**What it is.** A single-character programming typo caused GoAhead to shrink the 2048-bit
Diffie-Hellman key (the large secret number that protects a session) down to a single byte on
devices built against the **Mbed TLS** library. The resulting "key" is trivially breakable.

**Why it is serious — and why it is only Medium.** For affected TLS 1.2 DHE-RSA sessions, anyone
who can *passively record* the traffic can reconstruct the keys and decrypt the entire session,
destroying confidentiality and forward secrecy. However, the attack only works if the *client*
accepts such an absurdly weak key. Modern clients (current browsers, OpenSSL, Java, Go) refuse it
and fall back to safe encryption, which limits real-world exposure — hence **Medium 5.9**. Legacy or
custom embedded clients that do not enforce a minimum key size remain at risk. TLS 1.3 and ECDHE
sessions are unaffected.

**Who is affected.** Devices built with the **Mbed TLS backend**, GoAhead **4.0.2 through 6.1.0**,
negotiating TLS 1.2 DHE-RSA with a permissive client.

---

## 4. Affected Versions and Fix Matrix

| TLS build | Affected GoAhead versions | Required configuration to be exposed | Fix / mitigation |
|-----------|---------------------------|--------------------------------------|------------------|
| **OpenSSL-compatible** (SA-0006) | 3.4.5 – 6.1.0 | mTLS enabled with a CRL configured | **Upgrade to 6.1.1+** |
| **Mbed TLS** (SA-0005) | 4.0.2 – 6.1.0 | TLS 1.2 DHE-RSA with a permissive client | **Upgrade to 6.1.1+**, disable finite-field DHE suites, or use the OpenSSL backend |
| **LibreSSL legacy verifier** (SA-0004) | ≤ 6.1.0 (LibreSSL 3.2.x / 3.3.2–3.3.6) | `VERIFY_PEER=1` and `VERIFY_ISSUER=0` | Set `VERIFY_ISSUER=1` with a trusted CA bundle, or use OpenSSL / LibreSSL 4.x; **upgrade to 6.1.1+** |

**Fixed release:** GoAhead **6.1.1** (2 August 2026). All three fixes are backend-agnostic
defence-in-depth corrections and require no configuration or API changes.

---

## 5. Recommended Actions

**Priority 1 — Upgrade.** Update all GoAhead-based devices to **6.1.1 or later**. For devices you do
not build yourself, contact the device vendor for firmware that embeds GoAhead ≥ 6.1.1.

**Priority 2 — Monitor and investigate.** The included `goAheadShark.ps1` passively watches a
selected network interface for TLS handshakes matching the DH-parameter indicator described in
Section 6. It is not a host-discovery or vulnerability-scanning tool.

**Priority 3 — Interim mitigations where upgrade is not immediately possible:**
- **For the chain-depth bypass (SA-0004):** enable issuer verification — set
  `ME_GOAHEAD_SSL_VERIFY_ISSUER=1` with a trusted CA bundle. This closes the bypass.
- **For the DH truncation (SA-0005):** disable finite-field DHE cipher suites (prefer ECDHE /
  TLS 1.3), or rebuild against the OpenSSL backend.
- **For the CRL bypass (SA-0006):** there is **no safe configuration workaround** — revocation
  cannot be enforced on vulnerable builds. Upgrade is required. Until then, treat revoked
  certificates as *not* contained and apply compensating controls (network ACLs, reissuing CA,
  additional authentication layers).

**Priority 4 — Post-upgrade validation.** After patching, confirm the vendor-recommended TLS
configuration and, for mTLS deployments, verify through an authorized test that a known-revoked
certificate is rejected.

---

## 6. Using the included PowerShell monitor

`goAheadShark.ps1` passively monitors packets visible on one network interface and reports TLS
handshake packets matching the byte pattern configured in the script. It does not connect to
targets, enumerate hosts, validate GoAhead versions, test authentication, or establish that a device
is vulnerable. A matching packet is an indicator to investigate, not proof of exposure.

### Requirements

- Windows with PowerShell 5.1 or later.
- Wireshark installed, with `tshark.exe` at
  `C:\Program Files\Wireshark\tshark.exe`.
- Permission to capture traffic on the selected interface. Run PowerShell elevated if required by
  your Wireshark/Npcap setup.
- The BurntToast PowerShell module. If it is not installed, the script attempts to install it for
  the current user from the configured PowerShell repository.

### Configure and run

1. In `goAheadShark.ps1`, set `$Interface` to the interface name shown by `tshark -D`.
2. Set `$Ports` to the TLS ports you want to monitor; the default is `443 or 8443`.
3. Optionally adjust `$LogFile` to choose where matching packets are logged.
4. From the directory containing the script, run:

   ```powershell
   .\goAheadShark.ps1
   ```

The script prints a monitoring message, shows a Windows toast and plays a notification sound for
each match, and appends the packet timestamp and addresses to the log file. Press `Ctrl+C` to stop.

Only monitor traffic on networks and interfaces you are authorized to observe. Results are limited
to packets visible to the selected interface and the configured ports and filter; no alert does not
establish that a service or device is unaffected.

---

## 7. References

- FoxIO — *Choose Your Backend: Three TLS Bugs in GoAhead* (26 Oct 2026):
  https://foxio.io/blog/choose-your-backend-three-tls-bugs-in-goahead
- GOAHEAD-SA-2026-0004 / CVE-2026-115884 (chain-depth bypass):
  https://github.com/embedthis/goahead/security/advisories/GHSA-r392-vqwx-3r4g
- GOAHEAD-SA-2026-0005 (Mbed TLS DH truncation):
  https://github.com/embedthis/goahead/security/advisories/GHSA-fmvx-2xfx-2gq4
- GOAHEAD-SA-2026-0006 / CVE-2026-115881 (OpenSSL CRL disabled):
  https://github.com/embedthis/goahead/security/advisories/GHSA-5m75-xq69-c3c5
- GoAhead SSL documentation: https://www.embedthis.com/goahead/doc/users/ssl.html

### Disclosure timeline
- 22 Apr 2026 — LibreSSL finding reported
- 27 Apr 2026 — Mbed TLS finding reported
- 30 Apr 2026 — OpenSSL finding reported
- 02 Aug 2026 — GoAhead 6.1.1 released (all fixes)
- 12 Oct 2026 — Advisories published
- 26 Oct 2026 — FoxIO blog published
