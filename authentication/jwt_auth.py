# authentication/jwt_auth.py
from urllib.parse import parse_qs
from channels.middleware import BaseMiddleware
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.backends import TokenBackend
from django.conf import settings
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser

User = get_user_model()

@database_sync_to_async
def get_user(user_id):
    return User.objects.get(pk=user_id)

class JwtAuthMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        query = parse_qs(scope["query_string"].decode())
        token = None
        if "token" in query:
            token = query["token"][0]
        if token:
            try:
                tb = TokenBackend(algorithm=settings.SIMPLE_JWT.get("ALGORITHM","HS256"), signing_key=settings.SECRET_KEY)
                validated = tb.decode(token, verify=True)
                uid = validated.get(settings.SIMPLE_JWT.get("USER_ID_CLAIM","user_id"))
                scope["user"] = await get_user(int(uid))
            except Exception:
                scope["user"] = AnonymousUser()
        return await super().__call__(scope, receive, send)