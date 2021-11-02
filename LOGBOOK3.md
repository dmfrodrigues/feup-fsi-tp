
# Trabalho realizado na Semana #3

## **CVE-2020-6109**

## Identification
- Exploitable path traversal vulnerability, caused by improper limitation of pathname (CWE 22)
- Affects the Zoom client (v4.6.10), for Windows, macOS and Linux systems
- Chat supports a `giphy` extension, using special XMPP messages with URLs to fetch GIFs. URLs are fetched without sanitization.
- Allows directory traversal and arbitrary file write outside Zoom's installation directory

## Cataloguing
- Discovered and reported by Cisco Talos (see TALOS-2020-1055)
- Disclosed to vendor on 2020-04-16, released to the public on 2020-06-03
- CVSS severity 3.x score of 9.8 (critical); CVSS 2.x score of 7.5 (high)
- Zoom announced plans to revamp their bug bounty program on April 2020, the same month this vulnerability was disclosed

## Exploit
- An example of a malicious XMPP message is given in the corresponding Talos Vulnerability Report
- Changing the URL for the retrieval of the `giphy` file allows the download of an arbitrary file
- Crafting a special `id` attribute for the `giphy` tag allows writing a file in an arbitrary location
- There are no known Metasploit modules, but the vulnerability is well documented in the Talos Report

## Attacks
- No known reports of successful attacks, vulnerabilty patched since 2020-04-21
- On Windows systems using NTFS, NTFS alternative streams can potentially be abused to change configuration files or affect lock files
- Arbitrary file write could potentially be abused in conjunction with other vulnerabilities for arbitrary code execution
- Low access complexity, no authentication needed