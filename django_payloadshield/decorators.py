"""
Decorators for automatic payload encryption/decryption in Django views.
Supports multiple encryption types via the pluggable EncryptionHandler
interface. Configure keys globally with PayloadShieldEnc.init(...) before
using any of these decorators.
"""

import inspect
import json
from functools import wraps
from typing import Any, Callable

from django.http import HttpRequest, JsonResponse

from .config import PayloadShieldEnc
from .crypto import get_handler


def _wrap_encrypted(data: Any) -> dict:
    """Normalize a view's return value into a dict payload before encoding."""
    return data if isinstance(data, dict) else {"data": data}


def _unwrap_response(result: Any) -> Any:
    """Extract the JSON-able payload from a view's return value."""
    if isinstance(result, JsonResponse):
        return json.loads(result.content.decode("utf-8"))
    return result


def _parse_request_body(request: HttpRequest) -> Any:
    """Parse the raw request body as JSON, returning None if it's empty."""
    if not request.body:
        return None
    return json.loads(request.body.decode("utf-8"))


def _decrypt_body(handler, request: HttpRequest):
    """
    Decrypt an ``{"encrypted": "..."}`` request body in place, exposing the
    result as ``request.decrypted_data``.

    Returns a JsonResponse on failure, or None on success (including when
    there was nothing to decrypt).
    """
    body = _parse_request_body(request)
    if not (isinstance(body, dict) and "encrypted" in body):
        return None

    config = PayloadShieldEnc.get_config()
    try:
        request.decrypted_data = handler.decode(body["encrypted"], config)
    except Exception as e:
        return JsonResponse(
            {"error": f"Failed to decrypt request: {str(e)}"}, status=400
        )
    return None


class PayloadShield:
    """
    Namespace of decorator factories for encrypting/decrypting Django view
    request and response payloads.

    Usage:
        PayloadShieldEnc.init({"Key": "..."})

        @PayloadShield.encrypt("base64")
        def view(request): ...

        @PayloadShield.decrypt("base64")
        def view(request):
            data = request.decrypted_data
            ...

        @PayloadShield.crypt("base64")
        def view(request):
            data = request.decrypted_data
            ...
    """

    @staticmethod
    def encrypt(encryption_type: str = "base64") -> Callable:
        """
        Decorator that encrypts the view's response payload only.

        The response is wrapped as ``{"encrypted": "<encoded-data>"}``.
        """
        handler = get_handler(encryption_type)

        def decorator(func: Callable) -> Callable:
            if inspect.iscoroutinefunction(func):
                @wraps(func)
                async def async_wrapper(request: HttpRequest, *args, **kwargs):
                    result = await func(request, *args, **kwargs)
                    config = PayloadShieldEnc.get_config()
                    encoded = handler.encode(_wrap_encrypted(_unwrap_response(result)), config)
                    return JsonResponse({"encrypted": encoded})

                return async_wrapper

            @wraps(func)
            def wrapper(request: HttpRequest, *args, **kwargs):
                result = func(request, *args, **kwargs)
                config = PayloadShieldEnc.get_config()
                encoded = handler.encode(_wrap_encrypted(_unwrap_response(result)), config)
                return JsonResponse({"encrypted": encoded})

            return wrapper

        return decorator

    @staticmethod
    def decrypt(encryption_type: str = "base64") -> Callable:
        """
        Decorator that decrypts the incoming request payload only.

        Expects the request body to be ``{"encrypted": "<encoded-data>"}``.
        The decrypted value is exposed to the view as
        ``request.decrypted_data``.
        """
        handler = get_handler(encryption_type)

        def decorator(func: Callable) -> Callable:
            if inspect.iscoroutinefunction(func):
                @wraps(func)
                async def async_wrapper(request: HttpRequest, *args, **kwargs):
                    error_response = _decrypt_body(handler, request)
                    if error_response is not None:
                        return error_response
                    return await func(request, *args, **kwargs)

                return async_wrapper

            @wraps(func)
            def wrapper(request: HttpRequest, *args, **kwargs):
                error_response = _decrypt_body(handler, request)
                if error_response is not None:
                    return error_response
                return func(request, *args, **kwargs)

            return wrapper

        return decorator

    @staticmethod
    def crypt(encryption_type: str = "base64") -> Callable:
        """
        Decorator that decrypts the incoming request payload and encrypts
        the outgoing response payload using the same encryption type.
        """
        handler = get_handler(encryption_type)

        def decorator(func: Callable) -> Callable:
            if inspect.iscoroutinefunction(func):
                @wraps(func)
                async def async_wrapper(request: HttpRequest, *args, **kwargs):
                    error_response = _decrypt_body(handler, request)
                    if error_response is not None:
                        return error_response
                    result = await func(request, *args, **kwargs)
                    config = PayloadShieldEnc.get_config()
                    encoded = handler.encode(_wrap_encrypted(_unwrap_response(result)), config)
                    return JsonResponse({"encrypted": encoded})

                return async_wrapper

            @wraps(func)
            def wrapper(request: HttpRequest, *args, **kwargs):
                error_response = _decrypt_body(handler, request)
                if error_response is not None:
                    return error_response
                result = func(request, *args, **kwargs)
                config = PayloadShieldEnc.get_config()
                encoded = handler.encode(_wrap_encrypted(_unwrap_response(result)), config)
                return JsonResponse({"encrypted": encoded})

            return wrapper

        return decorator
