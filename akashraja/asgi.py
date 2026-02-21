# asgi.py
import os
import django
from django.core.asgi import get_asgi_application

# Set settings module first
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'akashraja.settings')
django.setup()

# Get application
django_asgi_app = get_asgi_application()

from channels.routing import ProtocolTypeRouter, URLRouter
from channels.sessions import SessionMiddlewareStack

from game.middleware import JWTAuthMiddleware
from game.routing import websocket_urlpatterns

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": JWTAuthMiddleware(
        URLRouter(
            websocket_urlpatterns
        )
    ),
})
