"""
Example Django application demonstrating every PayloadShield encryption
handler. Also used as a fixture by the automated test suite
(tests/test_all_crypts.py).

Run the server:
    python main.py runserver

Test with Postman:
    1. Start the server (command above), then open Postman.
    2. Set the base URL to http://127.0.0.1:8000.
    3. On startup this module prints one block per handler with the exact
       GET/POST URLs and a ready-to-paste JSON body - copy those straight
       into a Postman request (Body -> raw -> JSON).
    4. GET routes (e.g. /aes) need no body and return {"encrypted": "..."}.
       POST .../dec and .../cry routes expect {"encrypted": "..."} as the
       raw JSON body; .../cry additionally returns an encrypted response.
"""

import json
import sys
from importlib.metadata import version
from pathlib import Path

import django
from django.conf import settings

BASE_DIR = Path(__file__).resolve().parent
COMPYPS_VERSION = version("compyps")
DJANGOPS_VERSION = version("django_payloadshield")

if not settings.configured:
    settings.configure(
        DEBUG=True,
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF=__name__,
        SECRET_KEY="payloadshield-example-secret-key",
        MIDDLEWARE=[
            "django.middleware.common.CommonMiddleware",
        ],
    )
    django.setup()

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, x25519
from django.http import JsonResponse
from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from django_payloadshield import PayloadShield, PayloadShieldEnc, get_handler

SYMMETRIC_KEY = "12345678901234567890123456789012"  # 32 bytes

# Maps each handler name to the route prefix registered below, and doubles
# as the canonical list of every built-in encryption type.
ROUTE_PREFIX = {
    "base64": "base",
    "fernet": "fernet",
    "aes-gcm-256": "aes",
    "chacha20-poly1305": "chacha",
    "rsa-hybrid": "rsa",
    "ecdh-aes-gcm": "ecdh",
    "ecies": "ecies",
    "hpke": "hpke",
}
ALL_CRYPT_TYPES = list(ROUTE_PREFIX.keys())


# ----------------------------------------------------------------------------
# Generate (or reuse) the PEM key pairs each asymmetric handler needs.
# ----------------------------------------------------------------------------
def _write_pem_pair_if_missing(private_path: Path, public_path: Path, private_key) -> None:
    """Persist a freshly generated key pair to disk unless both files already exist."""
    if private_path.exists() and public_path.exists():
        return

    private_path.write_text(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
    )
    public_path.write_text(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
    )


RSA_PRIVATE_PEM_PATH = BASE_DIR / "private.pem"
RSA_PUBLIC_PEM_PATH = BASE_DIR / "public.pem"
EC_PRIVATE_PEM_PATH = BASE_DIR / "ec_private.pem"
EC_PUBLIC_PEM_PATH = BASE_DIR / "ec_public.pem"
HPKE_PRIVATE_PEM_PATH = BASE_DIR / "hpke_private.pem"
HPKE_PUBLIC_PEM_PATH = BASE_DIR / "hpke_public.pem"

_write_pem_pair_if_missing(
    RSA_PRIVATE_PEM_PATH, RSA_PUBLIC_PEM_PATH,
    rsa.generate_private_key(public_exponent=65537, key_size=2048),
)
_write_pem_pair_if_missing(
    EC_PRIVATE_PEM_PATH, EC_PUBLIC_PEM_PATH,
    ec.generate_private_key(ec.SECP256R1()),
)
_write_pem_pair_if_missing(
    HPKE_PRIVATE_PEM_PATH, HPKE_PUBLIC_PEM_PATH,
    x25519.X25519PrivateKey.generate(),
)

PayloadShieldEnc.init({
    "Key": SYMMETRIC_KEY,                          # fernet, aes-gcm-256, chacha20-poly1305
    "PrivateKey": str(RSA_PRIVATE_PEM_PATH),       # rsa-hybrid (decrypt)
    "PublicKey": str(RSA_PUBLIC_PEM_PATH),         # rsa-hybrid (encrypt)
    "ECPrivateKey": str(EC_PRIVATE_PEM_PATH),      # ecdh-aes-gcm, ecies (decrypt)
    "ECPublicKey": str(EC_PUBLIC_PEM_PATH),        # ecdh-aes-gcm, ecies (encrypt)
    "HPKEPrivateKey": str(HPKE_PRIVATE_PEM_PATH),  # hpke (decrypt)
    "HPKEPublicKey": str(HPKE_PUBLIC_PEM_PATH),    # hpke (encrypt)
})


def _hello_payload() -> dict:
    return {
        "message": "Hello, PayloadShield!",
        "ComPyPS": COMPYPS_VERSION,
        "DjangoPS": DJANGOPS_VERSION,
    }


urlpatterns = []


def _register_crypt_routes(crypt_type: str) -> None:
    """Wire up GET /<prefix>, POST /<prefix>/dec and POST /<prefix>/cry for a handler."""
    prefix = ROUTE_PREFIX[crypt_type]

    @require_GET
    @PayloadShield.encrypt(crypt_type)
    def root(request):
        return _hello_payload()

    @csrf_exempt
    @require_POST
    @PayloadShield.decrypt(crypt_type)
    def decrypt_payload(request):
        return JsonResponse(request.decrypted_data)

    @csrf_exempt
    @require_POST
    @PayloadShield.crypt(crypt_type)
    def crypt_payload(request):
        return request.decrypted_data

    urlpatterns.append(path(f"{prefix}", root, name=f"{prefix}-root"))
    urlpatterns.append(path(f"{prefix}/dec", decrypt_payload, name=f"{prefix}-dec"))
    urlpatterns.append(path(f"{prefix}/cry", crypt_payload, name=f"{prefix}-cry"))


for _crypt_type in ALL_CRYPT_TYPES:
    _register_crypt_routes(_crypt_type)


@require_GET
def health(request):
    return JsonResponse({"status": "ok"})


urlpatterns.append(path("health", health, name="health"))


# ----------------------------------------------------------------------------
# Postman quick-start: print a ready-to-paste request per handler on startup.
# ----------------------------------------------------------------------------
def _print_postman_examples() -> None:
    sample_payload = {"message": "hello", "id": 1}
    config = PayloadShieldEnc.get_config()

    print("\n" + "=" * 70)
    print("Postman quick start - base URL http://127.0.0.1:8000")
    print("=" * 70)
    for crypt_type in ALL_CRYPT_TYPES:
        prefix = ROUTE_PREFIX[crypt_type]
        encrypted = get_handler(crypt_type).encode(sample_payload, config)
        body = json.dumps({"encrypted": encrypted})

        print(f"\n[{crypt_type}]")
        print(f"  GET  /{prefix}            -> {{\"encrypted\": \"...\"}}")
        print(f"  POST /{prefix}/dec  body: {body}")
        print(f"  POST /{prefix}/cry  body: {body}")
    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    _print_postman_examples()
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
