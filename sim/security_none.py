def security_overhead_ms() -> int:
    # System-1: no auth, no crypto
    return 0

def is_sniffable() -> bool:
    # System-1: payloads are cleartext
    return True
