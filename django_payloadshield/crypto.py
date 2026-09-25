"""Backward-compatible access to ComPyPS encryption handlers."""

from compyps.crypto import (
    AESGCM256EncryptionHandler,
    Base64EncryptionHandler,
    ChaChaEncryptionHandler,
    ECDHAESGCMEncryptionHandler,
    ECIESEncryptionHandler,
    EncryptionHandler,
    FernetEncryptionHandler,
    HPKEEncryptionHandler,
    HybridRSAEncryptionHandler,
    get_handler,
    register_handler,
)

__all__ = [
    "EncryptionHandler",
    "Base64EncryptionHandler",
    "FernetEncryptionHandler",
    "AESGCM256EncryptionHandler",
    "HybridRSAEncryptionHandler",
    "ChaChaEncryptionHandler",
    "ECDHAESGCMEncryptionHandler",
    "ECIESEncryptionHandler",
    "HPKEEncryptionHandler",
    "register_handler",
    "get_handler",
]
