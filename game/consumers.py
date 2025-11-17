# game/consumers.py
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from django_redis import get_redis_connection

from game.services import handle_create_challenge, handle_flip, handle_respond_challenge
from .models import GameSession
from .constants import LABEL_SIZES
from .utils import fire_and_forget  # optional

r = get_redis_connection("default")

User = get_user_model()


class GameConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        user = self.scope.get("user")
        if not user or not user.is_authenticated:
            await self.close(code=4001)
            return

        self.user = user
        self.room_name = None

        # Accept connection first so we can send errors if needed
        await self.accept()

        # Join personal group so server can send direct notifications
        await self.channel_layer.group_add(f"user_{self.user.id}", self.channel_name)

        # Check if session_id is provided in the URL
        session_id = self.scope["url_route"]["kwargs"].get("session_id")
        if session_id is not None:
            # Ensure user is allowed to join this game session
            can_join = await database_sync_to_async(self._user_can_join)(self.user.id, session_id)
            if not can_join:
                await self.close(code=4003)
                return

            self.room_name = f"game_{session_id}"
            await self.channel_layer.group_add(self.room_name, self.channel_name)

    async def receive_json(self, content, **kwargs):
        action = content.get("action")
        if not action:
            await self.send_json({"error": "Missing action."})
            return

        if action == "flip":
            await self._handle_flip(content)
        elif action == "create_challenge":
            await self._handle_create_challenge(content)
        elif action == "respond_challenge":
            await self._handle_respond_challenge(content)
        elif action == "get_state":
            await self._handle_get_state(content)
        else:
            await self.send_json({"error": f"Unknown action '{action}'."})

    # -------------------------
    # Action handlers
    # -------------------------

    async def _handle_flip(self, content):
        session_id = content.get("session_id")
        indices = content.get("indices", [])

        if session_id is None:
            await self.send_json({"error": "session_id is required."})
            return

        if len(indices) != 2:
            await self.send_json({"error": "Provide exactly two indices."})
            return

        # Ensure the user is a participant in this game
        can_join = await database_sync_to_async(self._user_can_join)(self.user.id, session_id)
        if not can_join:
            await self.send_json({"error": "You are not a participant in this game."})
            return

        try:
            idx1, idx2 = int(indices[0]), int(indices[1])
        except (TypeError, ValueError):
            await self.send_json({"error": "Indices must be integers."})
            return

        try:
            # Expected: payload (dict) with optional event info, and state (public state dict)
            payload, state = await database_sync_to_async(handle_flip)(
                int(session_id),
                self.user.id,
                idx1,
                idx2,
            )
        except ValueError as e:
            await self.send_json({"error": str(e)})
            return
        except Exception:
            # Don't leak internal errors to clients
            await self.send_json({"error": "An unexpected error occurred while processing the move."})
            return

        # Broadcast updated game state ONCE to everyone (including the actor).
        await self.channel_layer.group_send(
            f"game_{session_id}",
            {
                "type": "game_state",
                "state": state,
            },
        )

        # If the service indicates that the game ended, broadcast a dedicated end-game event.
        if isinstance(payload, dict) and payload.get("event") == "game_end":
            await self.channel_layer.group_send(
                f"game_{session_id}",
                {
                    "type": "game_end",
                    "results": payload.get("results"),
                    "state": state,
                },
            )

    async def _handle_create_challenge(self, content):
        """
        Create a challenge and notify the opponent via their personal group.
        Expects:
            opponent_id: int
            size: int (board size)
            label: int (difficulty / label code)
        """
        try:
            opponent_id = int(content["opponent_id"])
            size = int(content["size"])
            label = int(content["label"])
        except (KeyError, TypeError, ValueError):
            await self.send_json(
                {"error": "opponent_id, size, and label are required and must be valid integers."}
            )
            return

        if size not in LABEL_SIZES:
            await self.send_json({"error": "Invalid board size."})
            return

        try:
            # Service should return a serializable challenge object/dict
            challenge = await database_sync_to_async(handle_create_challenge)(
                challenger_id=self.user.id,
                opponent_id=opponent_id,
                size=size,
                label=label,
            )
        except ValueError as e:
            await self.send_json({"error": str(e)})
            return

        # Notify opponent via their personal group
        await self.channel_layer.group_send(
            f"user_{opponent_id}",
            {
                "type": "game_move",
                "payload": {
                    "event": "challenge_created",
                    "challenge": challenge,
                },
            },
        )

        # Confirm back to challenger
        await self.send_json(
            {
                "type": "challenge_created",
                "challenge": challenge,
            }
        )

    async def _handle_respond_challenge(self, content):
        """
        Respond to a challenge.
        Expects:
            challenge_id: int
            response: "accept" | "reject"
        """
        try:
            challenge_id = int(content["challenge_id"])
            response = content["response"]
        except (KeyError, TypeError, ValueError):
            await self.send_json({"error": "challenge_id and response are required."})
            return

        try:
            # Service should return something like:
            # {
            #   "status": "accepted" | "rejected",
            #   "session_id": <int or None>,
            #   "opponent_id": <int>,
            #   ...
            # }
            result = await database_sync_to_async(handle_respond_challenge)(
                user_id=self.user.id,
                challenge_id=challenge_id,
                response=response,
            )
        except ValueError as e:
            await self.send_json({"error": str(e)})
            return

        opponent_id = result.get("opponent_id")
        session_id = result.get("session_id")

        # Notify opponent about the response via their personal group
        if opponent_id:
            await self.channel_layer.group_send(
                f"user_{opponent_id}",
                {
                    "type": "game_move",
                    "payload": {
                        "event": "challenge_responded",
                        "result": result,
                    },
                },
            )

        # If a game session was created on accept, join the room
        if result.get("status") == "accepted" and session_id:
            self.room_name = f"game_{session_id}"
            await self.channel_layer.group_add(self.room_name, self.channel_name)

        # Respond to the current user
        await self.send_json(
            {
                "type": "challenge_responded",
                "result": result,
            }
        )

    async def _handle_get_state(self, content):
        """
        Fetch the current public state of a game session from Redis.
        """
        session_id = content.get("session_id")
        if session_id is None:
            await self.send_json({"error": "session_id is required."})
            return

        # Ensure user is in this session
        can_join = await database_sync_to_async(self._user_can_join)(self.user.id, session_id)
        if not can_join:
            await self.send_json({"error": "You are not a participant in this game."})
            return

        state = await database_sync_to_async(_read_public_state)(int(session_id))
        if state is None:
            await self.send_json({"error": "Game session not found or not initialized."})
            return

        await self.send_json({"type": "game_state", "state": state})

    # -------------------------
    # Channel layer handlers
    # -------------------------

    async def game_move(self, event):
        # Broadcasted event handler (personal or room-scoped notifications)
        await self.send_json({"type": "game_move", "payload": event["payload"]})

    async def game_state(self, event):
        # Broadcasted event handler for game state updates
        state = event.get("state")
        await self.send_json({"type": "game_state", "state": state})

    async def game_end(self, event):
        # Broadcasted event handler for game end
        await self.send_json(
            {
                "type": "game_end",
                "results": event.get("results"),
                "state": event.get("state"),
            }
        )

    async def disconnect(self, code):
        # Leave game room if joined
        if getattr(self, "room_name", None):
            await self.channel_layer.group_discard(self.room_name, self.channel_name)

        # Leave personal group
        if getattr(self, "user", None):
            await self.channel_layer.group_discard(f"user_{self.user.id}", self.channel_name)

    # -------------------------
    # Sync DB helper
    # -------------------------

    def _user_can_join(self, user_id, session_id):
        try:
            sess = GameSession.objects.get(pk=int(session_id))
            return user_id in (sess.player1_id, sess.player2_id)
        except GameSession.DoesNotExist:
            return False


# -------------------------
# Redis helpers (sync)
# -------------------------

def _session_keys(sid):
    base = f"game:{sid}:"
    return {
        "board": base + "board",
        "revealed": base + "revealed",
        "turn": base + "turn",
        "scores": base + "scores",
        "meta": base + "meta",
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
