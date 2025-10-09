# System-2 Methodology (Secure)

**Goal:** Address multipath-signature–induced eavesdropping via peer-to-peer authentication for energy-constrained IoT, using advanced gateway-assisted key generation and KIM-based physical-layer protection.

**Pipeline**
1) **Gateway keygen (TDD reciprocity):** ED and GW sample reciprocal channels; a 128-bit key is derived with lightweight bit-slicing + privacy amplification.
2) **Peer authentication (HMAC token + nonce exchange):** Lightweight handshake binds devices to the session key (gateway intelligence).
3) **KIM modulation:** Payload symbols are permuted by a key-indexed mapping; without the key, Eve's BER stays high and content remains unreadable.
4) **PLS stress knobs:** Optional multipath signature and pilot contamination simulate adversarial/harsh channels.
5) **Metrics:** Confidentiality ↑ ; modest ↑ in latency/energy due to handshake + mapping overheads.

**Why it is lightweight**
- No heavy public-key ops on IoT nodes.
- Minimal per-packet CPU (table-based permutation).
- Single short handshake per session.
