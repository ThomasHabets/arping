# Security Policy

## Supported versions

Security fixes are provided for the most recent release of Arping. Older
releases are not supported, as the newest version is expected to work backwards
compatibly even on very old systems; please confirm that an issue is still
present in the latest release before reporting it.

## Reporting a vulnerability

Please report suspected security vulnerabilities privately by email to Thomas
Habets at <thomas@habets.se>. Use a clear subject such as `[arping security]`
and do not open a public GitHub issue, discussion, or pull request for the
vulnerability.

If you feel it appropriate, use GPG to encrypt your report. Fingerprint of
<thomas@habets.se> GPG key:

```
 9907 8698 8A24 F52F 1C2E  87F6 39A4 9EEA 460A 0169
```

Include as much of the following as possible:

* The affected Arping version or commit.
* The operating system, architecture, and relevant build configuration.
* A description of the issue, its security impact, and the conditions needed
  to exploit it.
* Steps to reproduce the issue, including a minimal proof of concept or crash
  input when available.
* Any suggested mitigation or fix.
* Whether the issue has been disclosed elsewhere or is subject to a disclosure
  deadline.

The maintainer will try to acknowledge the report promptly, investigate it,
and coordinate a fix and disclosure with the reporter. Please allow a
reasonable amount of time for a response and remediation before publishing
details. If you do not receive a response, follow up using the same email
address.

Arping intentionally creates and receives low-level network packets and may be
run with elevated privileges or `CAP_NET_RAW`. Those properties alone are not
vulnerabilities. Reports about memory corruption, privilege handling, sandbox
escape, or unsafe processing of network input are especially useful. Issues
that affect only libnet, libpcap, or another dependency should be reported to
that project; report them here as well if Arping requires a separate change.

Please state whether you would like to be credited in any release notes or
advisory.
