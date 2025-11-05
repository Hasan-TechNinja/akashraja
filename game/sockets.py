import json
import socketio
from django.contrib.auth import get_user_model
from django.conf import settings
from django.db import connections
from django.apps import apps
from django_redis import get_redis_connection

from .constants import LABEL_SIZES

from .models import GameSession

User = get_user_model()
r = get_redis_connection("default")

# CORS as needed; lock this down for prod
sio = socketio.AsyncServer(
    async_mode='asgi',
    cors_allowed_origins='*',  # set your frontend origin(s) in prod
    json=json,
)

# --- Helpers ---
def _keys(sid):  # session_id
    base = f"game:{sid}:"
    return {
        "board":   base+"board",
        "revealed":base+"revealed",
        "turn":    base+"turn",
        "scores":  base+"scores",
        "meta":    base+"meta",
    }

LABEL_SIZES = {1: 4, 2: 6, 3: 10, 4: 12, 5: 16, 6: 20, 7: 24}

async def _read_public_state(session_id: int):
    keys = _keys(session_id)
    meta = r.hgetall(keys["meta"])
    if not meta:
        return None
    size = int(meta[b"size"])
    label = int(meta[b"label"])
    turn_raw = r.get(keys["turn"])
    turn_uid = int(turn_raw) if turn_raw else None
    b = [int(x) for x in r.lrange(keys["board"], 0, -1)]
    revealed = {int(i) for i in r.smembers(keys["revealed"])}
    scores = {k.decode(): int(v) for k, v in r.hgetall(keys["scores"]).items()}
    reveal_all_until = int(meta.get(b"reveal_all_until", b"0"))

    tiles = [ (b[i] if i in revealed else None) for i in range(size) ]
    return {
        "session_id": session_id,
        "label": label,
        "size": size,
        "tiles": tiles,
        "turn_user_id": turn_uid,
        "scores": scores,
        "reveal_all_until": reveal_all_until,
    }

async def _user_can_join(user_id: int, session_id: int) -> bool:
    try:
        sess = GameSession.objects.get(pk=session_id)
        return user_id in (sess.player1_id, sess.player2_id)
    except GameSession.DoesNotExist:
        return False

# --- Auth note ---
# For simplicity, we accept user_id via query param ?user_id=...
# In production, validate via session cookie or JWT.
@sio.event
async def connect(sid, environ, auth):
    # Parse query string for user_id
    # environ['QUERY_STRING'] like: b"user_id=21"
    query = environ.get('QUERY_STRING', b'')
    user_id = None
    if query:
        try:
            q = dict(
                kv.split('=', 1) for kv in query.decode().split('&') if '=' in kv
            )
            if "user_id" in q:
                user_id = int(q["user_id"])
        except Exception:
            pass

    if not user_id:
        return False  # reject connection

    # Put socket in a personal room for direct notifications
    await sio.save_session(sid, {"user_id": user_id})
    await sio.enter_room(sid, f"user:{user_id}")

    # Optional: notify client they are connected
    await sio.emit("connected", {"ok": True, "user_id": user_id}, to=sid)

@sio.event
async def disconnect(sid):
    # Nothing special; rooms auto-cleanup
    pass

# Client asks to join a game room
# payload: {"session_id": 1}
@sio.event
async def game_join(sid, data):
    sess = await sio.get_session(sid)
    user_id = sess.get("user_id")
    session_id = int(data.get("session_id"))

    if not await _user_can_join(user_id, session_id):
        await sio.emit("error", {"detail": "Forbidden for this session."}, to=sid)
        return

    room = f"game:{session_id}"
    await sio.enter_room(sid, room)
    state = await _read_public_state(session_id)
    await sio.emit("game_state", state, to=sid)

# Client wants a fresh state (manual refresh)
@sio.event
async def game_state_request(sid, data):
    session_id = int(data.get("session_id"))
    state = await _read_public_state(session_id)
    await sio.emit("game_state", state, to=sid)
