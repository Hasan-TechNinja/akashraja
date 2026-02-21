# asgi.py
import os
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'akashraja.settings')

# Standard Django ASGI app for HTTP
django_asgi_app = get_asgi_application()

from channels.routing import ProtocolTypeRouter, URLRouter
from channels.sessions import SessionMiddlewareStack

from game.middleware import JWTAuthMiddleware           # <-- your custom JWT middleware
from game.routing import websocket_urlpatterns           # <-- your WS URLs

# Standard Django ASGI app for HTTP
django_asgi_app = get_asgi_application()

application = ProtocolTypeRouter({
    # HTTP requests
    "http": django_asgi_app,

    # WebSocket connections
    "websocket": JWTAuthMiddleware(                      # <-- JWT auth applied here
        URLRouter(
            websocket_urlpatterns                       # <-- game/ws routing
        )
    ),
})
