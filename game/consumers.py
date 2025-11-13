# game/consumers.py
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from .models import GameSession
from .utils import fire_and_forget  # optional
from django_redis import get_redis_connection
from .constants import LABEL_SIZES

r = get_redis_connection("default")

User = get_user_model()

class GameConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        user = self.scope.get("user")
        # If using JWT middleware, scope['user'] will be set; otherwise check session
        if not user or not user.is_authenticated:
            await self.close(code=4001)
            return
        self.user = user
        await self.accept()
        # Join a personal group so server can send direct notifications
        await self.channel_layer.group_add(f"user_{self.user.id}", self.channel_name)

    async def receive_json(self, content):
        # Expect messages like: {"action":"join","session_id": 5} or {"action":"flip","session_id":5,"indices":[1,2]}
        action = content.get("action")
        if action == "join":
            session_id = int(content["session_id"])
            room = f"game_{session_id}"
            # permission check
            allowed = await database_sync_to_async(self._user_can_join)(self.user.id, session_id)
            if not allowed:
                await self.send_json({"error":"forbidden"})
                return
            self.room_name = room
            await self.channel_layer.group_add(room, self.channel_name)
            # send current state back
            state = await database_sync_to_async(_read_public_state)(session_id)  # wrap read function
            await self.send_json({"type":"game_state","state":state})
        elif action == "flip":
            # forward to server logic or call existing REST flip endpoint
            # simpler: call channel layer to notify other players
            await self.channel_layer.group_send(self.room_name, {"type":"game.move", "payload": content})
        # ... handle other actions

    async def game_move(self, event):
        # broadcasted event handler
        await self.send_json({"type":"game_move", "payload": event["payload"]})

    async def disconnect(self, code):
        if hasattr(self, "room_name"):
            await self.channel_layer.group_discard(self.room_name, self.channel_name)
        # Remove from personal group
        if hasattr(self, "user") and getattr(self, "user", None):
            await self.channel_layer.group_discard(f"user_{self.user.id}", self.channel_name)

    async def game_state(self, event):
        # server sends full state
        await self.send_json({"type": "game_state", "state": event.get("state")})

    async def challenge_accepted(self, event):
        await self.send_json({"type": "challenge_accepted", "session": event.get("session")})

    # sync DB helper
    def _user_can_join(self, user_id, session_id):
        try:
            sess = GameSession.objects.get(pk=session_id)
            return user_id in (sess.player1_id, sess.player2_id)
        except GameSession.DoesNotExist:
            return False


def _session_keys(sid):
    base = f"game:{sid}:"
    return {
        "board":   base + "board",
        "revealed": base + "revealed",
        "turn":     base + "turn",
        "scores":   base + "scores",
        "meta":     base + "meta",
    }


def _read_public_state(session_id: int):
    keys = _session_keys(session_id)
    meta = r.hgetall(keys["meta"])
    if not meta:
        return None

    size = int(meta[b"size"])
    label = int(meta[b"label"])
    turn_raw = r.get(keys["turn"])
    turn_uid = int(turn_raw) if turn_raw else None
    board = [int(x) for x in r.lrange(keys["board"], 0, -1)]
    revealed = {int(i) for i in r.smembers(keys["revealed"])}
    scores = {k.decode(): int(v) for k, v in r.hgetall(keys["scores"]).items()}
    reveal_all_until = int(meta.get(b"reveal_all_until", b"0"))

    tiles = [(board[i] if i in revealed else None) for i in range(size)]
    return {
        "session_id": session_id,
        "label": label,
        "size": size,
        "tiles": tiles,
        "turn_user_id": turn_uid,
        "scores": scores,
        "reveal_all_until": reveal_all_until,
    }