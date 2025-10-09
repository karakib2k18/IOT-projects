def security_overhead_ms() -> int:
    """No auth, no PLS, no encryption → zero overhead in System 1."""
    return 0

def is_sniffable() -> bool:
    """All traffic is cleartext and routed via gateway → sniffable."""
    return True
