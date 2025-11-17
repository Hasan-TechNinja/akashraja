# game/middleware.py
import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from channels.db import database_sync_to_async
from urllib.parse import parse_qs

User = get_user_model()


class JWTAuthMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        # Extract token from headers
        headers = dict(scope.get("headers", []))
        token = None

        # Look for Authorization: Bearer <token>
        auth_header = headers.get(b"authorization")
        if auth_header:
            auth_header = auth_header.decode()
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        # Support token=? in query params (browser fallback)
        if not token:
            query = parse_qs(scope.get("query_string", b"").decode())
            token_list = query.get("token")
            if token_list:
                token = token_list[0]

        # Default to Anonymous if no token
        if not token:
            scope["user"] = None
            return await self.app(scope, receive, send)

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user_id = payload.get("user_id") or payload.get("id")
        except Exception:
            scope["user"] = None
            return await self.app(scope, receive, send)

        user = await self.get_user(user_id)
        scope["user"] = user
        return await self.app(scope, receive, send)

    @database_sync_to_async
    def get_user(self, user_id):
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None
