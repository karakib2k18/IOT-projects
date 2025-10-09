# IoT_Vulnerable_S1 → System-1 (Vulnerable) + System-2 (Secure)

Two comparable IoT simulations:

- **System-1 (Vulnerable):** all traffic via gateway, no encryption/auth ⇒ eavesdropper intercepts almost everything.
- **System-2 (Secure):** gateway-assisted key generation (TDD reciprocity), P2P authentication (HMAC), Key-Indexed
  Modulation (KIM) + key-dither (PLS), ESS feature checks (gateway intelligence), optional multipath/pilot stress.

## Quickstart
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# System-1
python3 sim/runner_vulnerable.py

# System-2
python3 sim/runner_secure.py

# Compare summaries
python3 analysis/compare_s1_s2.py
