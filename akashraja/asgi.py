import os
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.core.asgi import get_asgi_application
import game.routing as game_routing

# JWT middleware that reads ?token=ACCESS_TOKEN and sets scope['user']
from authentication.jwt_auth import JwtAuthMiddleware

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'akashraja.settings')

# Use JwtAuthMiddleware to allow token-auth via querystring, falling back to
# Django session auth provided by AuthMiddlewareStack. This lets clients
# connect with either ?token=ACCESS_TOKEN or a valid session cookie.
application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": JwtAuthMiddleware(
        AuthMiddlewareStack(
            URLRouter(game_routing.websocket_urlpatterns)
        )
    ),
})
