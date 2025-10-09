import hmac, hashlib, os

def mac_k(key: bytes, msg: bytes, tag_len=8) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()[:tag_len]

def make_token(key: bytes, ed_id: str, pd_id: str, epoch: int, params: bytes=b'') -> bytes:
    msg = ed_id.encode() + b'|' + pd_id.encode() + b'|' + str(epoch).encode() + b'|' + params
    return mac_k(key, msg)

def verify_token(key: bytes, token: bytes, ed_id: str, pd_id: str, epoch: int) -> bool:
    return make_token(key, ed_id, pd_id, epoch) == token

def p2p_handshake_messages(key: bytes):
    # Minimal 2-message nonce exchange (lightweight)
    n1 = os.urandom(4)
    m1 = n1 + mac_k(key, n1)
    n2 = os.urandom(4)
    m2 = n2 + mac_k(key, n1 + n2)
    return m1, m2
