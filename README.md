# Django Payload Shield

Pluggable Django decorators for encrypting and decrypting request and
response payloads. Configure your keys once, then annotate any view with
`@PayloadShield.encrypt`, `@PayloadShield.decrypt`, or `@PayloadShield.crypt`.

## Key Features

- **Pluggable encryption**: base64, Fernet, AES-GCM-256, ChaCha20-Poly1305,
  Hybrid RSA+AES, ECDH+AES-GCM, ECIES, and HPKE (RFC 9180) ship out of the
  box; register your own with `register_handler(...)`.
- **One-time key configuration**: `PayloadShieldEnc.init({...})` sets keys
  globally for all decorators.
- **View-agnostic**: no changes needed to your view logic besides adding a
  decorator and reading `request.decrypted_data`.
- **Sync and async friendly**: works with both regular `def` and `async def`
  Django views.

## Installation

```bash
pip install django_payloadshield
```

## Quick Start

```python
from django.urls import path
from django_payloadshield import PayloadShield, PayloadShieldEnc

# Configure encryption keys once, at startup (e.g. in settings.py or AppConfig.ready()).
PayloadShieldEnc.init({
    "Key": "my-symmetric-key",
})

@PayloadShield.encrypt("base64")
def get_data(request):
    return {"message": "hello", "data": "world"}

@PayloadShield.decrypt("base64")
def process_data(request):
    return {"received": request.decrypted_data, "status": "success"}

@PayloadShield.crypt("base64")
def secure_endpoint(request):
    return {"processed": request.decrypted_data}

urlpatterns = [
    path("api/data", get_data),
    path("api/process", process_data),
    path("api/secure", secure_endpoint),
]
```

## Initialization: `PayloadShieldEnc.init(...)`

Call once before serving requests. Every decorator reads this shared
configuration at call time.

```python
PayloadShieldEnc.init({
    "Key": key,               # symmetric key: fernet, aes-gcm-256, chacha20-poly1305
    "PrivateKey": "string",   # RSA/hybrid private key (file path or PEM content)
    "PublicKey": "string",    # RSA/hybrid public key (file path or PEM content)
    "ECPrivateKey": "string", # EC (P-256) private key (file path or PEM content)
    "ECPublicKey": "string",  # EC (P-256) public key (file path or PEM content)
    "HPKEPrivateKey": "string", # X25519 private key (file path or PEM content)
    "HPKEPublicKey": "string",  # X25519 public key (file path or PEM content)
})
```

| Field | Used by | Accepts |
|---|---|---|
| `Key` | `fernet`, `aes-gcm-256`, `chacha20-poly1305` | Raw key string. `aes-gcm-256` and `chacha20-poly1305` require the key to resolve to exactly 32 bytes (UTF-8 or base64 encoded). |
| `PrivateKey` | `rsa-hybrid` (decrypt) | File path to a PEM file, or the raw PEM content (RSA key). |
| `PublicKey` | `rsa-hybrid` (encrypt) | File path to a PEM file, or the raw PEM content (RSA key). |
| `ECPrivateKey` | `ecdh-aes-gcm`, `ecies` (decrypt) | File path to a PEM file, or the raw PEM content (EC P-256 key). |
| `ECPublicKey` | `ecdh-aes-gcm`, `ecies` (encrypt) | File path to a PEM file, or the raw PEM content (EC P-256 key). |
| `HPKEPrivateKey` | `hpke` (decrypt) | File path to a PEM file, or the raw PEM content (X25519 key). |
| `HPKEPublicKey` | `hpke` (encrypt) | File path to a PEM file, or the raw PEM content (X25519 key). |

Only set the fields required by the encryption types you actually use.

## Decorators

All three live on the `PayloadShield` class and take an `encryption_type`
(default `"base64"`).

### `@PayloadShield.encrypt(encryption_type)`

Encrypts the response payload only.

```python
@PayloadShield.encrypt("base64")
def get_users(request):
    return [{"id": 1, "name": "Alice"}]

# Response: {"encrypted": "W3siaWQiOiAxLCAibmFtZSI6ICJBbGljZSJ9XQ=="}
```

### `@PayloadShield.decrypt(encryption_type)`

Decrypts the request payload only; the decrypted dict is exposed as
`request.decrypted_data`.

```python
@PayloadShield.decrypt("base64")
def login(request):
    credentials = request.decrypted_data
    return {"status": "success"}

# Expects: {"encrypted": "base64_encoded_json"}
```

### `@PayloadShield.crypt(encryption_type)`

Decrypts the request and encrypts the response.

```python
@PayloadShield.crypt("base64")
def secure_endpoint(request):
    return {"processed": request.decrypted_data}

# Expects: {"encrypted": "encrypted_data"}
# Returns: {"encrypted": "encrypted_data"}
```

Views that accept a decrypted body are typically POST-only and should be
paired with `@csrf_exempt` (raw JSON clients rarely send a CSRF token) and
`@require_POST`, applied outside the PayloadShield decorator.

## Built-in Encryption Handlers

| Name | Algorithm | Keys required | Security |
|---|---|---|---|
| `base64` | Base64 encoding | none | None — obfuscation only |
| `fernet` | Fernet (AES-128-CBC + HMAC) | `Key` | Symmetric, authenticated |
| `aes-gcm-256` | AES-256-GCM | `Key` (32 bytes) | Symmetric, authenticated |
| `chacha20-poly1305` | ChaCha20-Poly1305 | `Key` (32 bytes) | Symmetric, authenticated |
| `rsa-hybrid` | RSA-OAEP + AES-256-GCM | `PublicKey` (encrypt), `PrivateKey` (decrypt) | Asymmetric/hybrid |
| `ecdh-aes-gcm` | Ephemeral-static ECDH (P-256) + HKDF-SHA256 + AES-256-GCM | `ECPublicKey` (encrypt), `ECPrivateKey` (decrypt) | Asymmetric/hybrid, authenticated |
| `ecies` | ECIES: ECDH (P-256) + HKDF-SHA256 + AES-256-CTR + HMAC-SHA256 (encrypt-then-MAC) | `ECPublicKey` (encrypt), `ECPrivateKey` (decrypt) | Asymmetric/hybrid, authenticated |
| `hpke` | HPKE (RFC 9180) base mode: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305 | `HPKEPublicKey` (encrypt), `HPKEPrivateKey` (decrypt) | Asymmetric/hybrid, authenticated |

## Custom Handlers

Implement `EncryptionHandler` and register it — every decorator can then
use it by name.

```python
from typing import Any, Dict, Optional
from django_payloadshield import EncryptionHandler, register_handler, PayloadShield

class MyHandler(EncryptionHandler):
    def encode(self, data: Any, config: Optional[Dict[str, Any]] = None) -> str:
        ...

    def decode(self, encoded_data: str, config: Optional[Dict[str, Any]] = None) -> Any:
        ...

register_handler("my-handler", MyHandler())

@PayloadShield.crypt("my-handler")
def custom_endpoint(request):
    return request.decrypted_data
```

`config` is the dict returned by `PayloadShieldEnc.get_config()` — pull out
whatever keys your handler needs (`Key`, `PrivateKey`, `PublicKey`).

## How It Works

**Request decryption**: client sends `{"encrypted": "..."}` → decorator
decodes it with the configured handler → view reads `request.decrypted_data`.

**Response encryption**: view returns a dict → decorator encodes it with
the configured handler → client receives `{"encrypted": "..."}`.

## Errors

| Situation | Behavior |
|---|---|
| Request decryption fails | `400` response: `{"error": "Failed to decrypt request: ..."}` |
| Unknown `encryption_type` | `ValueError` raised when the decorator is applied: `Encryption handler '<name>' not found. Available handlers: ...` |
| Missing required key (e.g. no `Key` set for `fernet`) | `ValueError` raised when encoding/decoding: `... requires 'Key' to be set via PayloadShieldEnc.init(...)` |

## Testing

```bash
# Run the example app (also prints Postman-ready request examples)
cd examples
python main.py runserver

# Run the test suite
pytest
```

## Requirements

- Python 3.8+
- Django 3.2+
- cryptography 41+

## Project Layout

```
django_payloadshield/
    __init__.py
    config.py       # PayloadShieldEnc re-export
    crypto.py       # Encryption handlers re-export
    decorators.py   # PayloadShield decorator factories
examples/
    main.py         # Runnable Django app demoing every handler
tests/
    conftest.py
    test_config.py
    test_handlers.py
    test_decorators.py
    test_all_crypts.py
```
