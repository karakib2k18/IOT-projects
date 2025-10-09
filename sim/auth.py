import os, hmac, hashlib

def make_token(key: bytes, ed_id: str, pd_id: str, epoch: int) -> bytes:
    """
    >>> P2P auth token (bind IDs + epoch to the session key)
    """
    msg = f"{ed_id}|{pd_id}|{epoch}".encode()
    return hmac.new(key, msg, hashlib.sha256).digest()

def verify_token(key: bytes, token: bytes, ed_id: str, pd_id: str, epoch: int) -> bool:
    exp = make_token(key, ed_id, pd_id, epoch)
    return hmac.compare_digest(exp, token)

def p2p_handshake_messages(key: bytes):
    """
    >>> P2P 2-step nonce handshake (challenge/response)
    """
    n1 = os.urandom(12)
    tag1 = hmac.new(key, n1, hashlib.sha256).digest()[:8]
    n2 = os.urandom(12)
    tag2 = hmac.new(key, n2 + tag1, hashlib.sha256).digest()[:8]
    # return the messages that would go on air
    return (n1 + tag1), (n2 + tag2)
