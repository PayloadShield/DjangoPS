"""
Tests for PayloadShield decorators and PayloadShieldEnc initialization.
"""

import base64
import json

import pytest
from django.http import JsonResponse
from django.test import Client, override_settings
from django.urls import path

from django_payloadshield import PayloadShield, PayloadShieldEnc

PayloadShieldEnc.init({"Key": "test-symmetric-key"})


@PayloadShield.encrypt("base64")
def encrypt_only(request):
    return {"message": "hello"}


@PayloadShield.decrypt("base64")
def decrypt_only(request):
    return JsonResponse({"received": request.decrypted_data})


@PayloadShield.crypt("base64")
def crypt_both(request):
    return {"echo": request.decrypted_data}


urlpatterns = [
    path("encrypt-only", encrypt_only, name="encrypt-only"),
    path("decrypt-only", decrypt_only, name="decrypt-only"),
    path("crypt", crypt_both, name="crypt"),
]

@pytest.fixture(autouse=True)
def _use_module_urlconf():
    with override_settings(ROOT_URLCONF=__name__):
        yield


client = Client()


def _b64_encode(payload: dict) -> str:
    return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")


def _b64_decode(encoded: str) -> dict:
    return json.loads(base64.b64decode(encoded.encode("utf-8")).decode("utf-8"))


def test_encrypt_only_wraps_response():
    response = client.get("/encrypt-only")
    assert response.status_code == 200
    body = response.json()
    assert "encrypted" in body
    assert _b64_decode(body["encrypted"]) == {"message": "hello"}


def test_decrypt_only_reads_encrypted_request():
    payload = {"username": "admin", "password": "secret"}
    response = client.post(
        "/decrypt-only",
        data=json.dumps({"encrypted": _b64_encode(payload)}),
        content_type="application/json",
    )
    assert response.status_code == 200
    assert response.json() == {"received": payload}


def test_crypt_round_trips_request_and_response():
    payload = {"name": "Alice"}
    response = client.post(
        "/crypt",
        data=json.dumps({"encrypted": _b64_encode(payload)}),
        content_type="application/json",
    )
    assert response.status_code == 200
    body = response.json()
    assert "encrypted" in body
    assert _b64_decode(body["encrypted"]) == {"echo": payload}
