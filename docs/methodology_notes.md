# System 1 – Vulnerable Methodology Notes

**Intentional weaknesses**
- No peer-to-peer authentication or encryption
- No physical-layer security or artificial noise
- No gateway-based key generation or session keys
- All traffic routed via gateway in cleartext
- Eavesdropper succeeds with probability = 1.0

**What we expect**
- Confidentiality ≈ 0%
- Lowest latency and energy (no security overhead)
- Intercepted ≈ total messages
