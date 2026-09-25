"""Configures Django settings once, before any test module is imported."""

import django
from django.conf import settings

if not settings.configured:
    settings.configure(
        DEBUG=True,
        ALLOWED_HOSTS=["*"],
        SECRET_KEY="test-secret-key",
        ROOT_URLCONF=__name__,
    )
    django.setup()

# Placeholder urlconf used only until a test module overrides ROOT_URLCONF
# with its own module (via django.test.override_settings).
urlpatterns = []
