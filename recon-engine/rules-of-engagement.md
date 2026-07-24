# Rules of Engagement: A1 Recon Target

| Item | Rule |
|---|---|
| In scope | Only the `127.0.0.1:port` endpoints marked `IN` in the generated `scope.csv` |
| Out of scope | Every other address, port, local service, and the explicit loopback decoy |
| Allowed | Discovery, low-rate enumeration, vhost probing, authentication with credentials found inside the assigned target |
| Prohibited | Denial of service, destructive writes, persistence, malware, credential reuse elsewhere, internet scanning |
| Proof limit | Read the assigned `user.txt`; stop before privilege escalation |
| Hours | The published assessment window only |
| Stop condition | Any non-loopback destination, unexpected local service, unstable target, or evidence of non-synthetic data |
| Escalation | Stop, preserve output, and notify the assessment lead with UTC time and last command |

I understand and accept the scope.

Intern code: `UBI-2026-0257`  
Signed name: `Jahmir Vargas`  
UTC date/time: `2026-07-20T14:17:00Z`
