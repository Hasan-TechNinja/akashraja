# -----------------------------
# 3️⃣  Challenge: accept / decline
# -----------------------------
from .sockets import sio
from .utils import fire_and_forget
from .constants import LABEL_SIZES, IMAGE_IDS
from .utils import fire_and_forget
from rest_framework import generics, permissions, status, views
from rest_framework.response import Response
import random
import time
from django.utils import timezone
from django.conf import settings
from django.db import models, transaction
from django_redis import get_redis_connection
from .models import GameChallenge, GameSession
from .serializers import ChallengeCreateSerializer, ChallengeSerializer, SessionSerializer



class ChallengeRespondView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        accept = bool(request.data.get("accept"))
        try:
            ch = GameChallenge.objects.select_for_update().get(pk=pk)
        except GameChallenge.DoesNotExist:
            return Response({"detail": "Challenge not found"}, status=404)

        # ✅ Permission check
        if ch.opponent_id != request.user.id:
            return Response({"detail": "Not your challenge."}, status=403)

        if ch.status != "pending":
            return Response({"detail": "Already handled."}, status=400)

        with transaction.atomic():
            # --- Update challenge status ---
            ch.status = "accepted" if accept else "declined"
            ch.save()

            # --- If declined, stop here ---
            if not accept:
                return Response({"status": "declined"})

            # --- Create new GameSession ---
            session = GameSession.objects.create(
                player1=ch.challenger,
                player2=ch.opponent,
                label=ch.label,
            )

            # --- Initialize board in Redis ---
            keys = _session_keys(session.id)
            size = LABEL_SIZES[ch.label]
            images = random.sample(IMAGE_IDS, size // 2)
            board = images + images
            random.shuffle(board)

            # Reset Redis keys
            r.delete(keys["board"], keys["revealed"])
            r.rpush(keys["board"], *board)
            r.delete(keys["revealed"])
            r.hset(keys["scores"], mapping={"p1": 0, "p2": 0})
            r.set(keys["turn"], ch.challenger_id)
            reveal_ms = int((time.time() + 2.0) * 1000)
            r.hset(
                keys["meta"],
                mapping={
                    "label": ch.label,
                    "size": size,
                    "player1": ch.challenger_id,
                    "player2": ch.opponent_id,
                    "reveal_all_until": reveal_ms,
                },
            )

        # --- Serialize session data ---
        session_data = SessionSerializer(session).data

        # ======================================================
        # 🔔 SOCKET.IO LIVE NOTIFICATIONS (fire-and-forget)
        # ======================================================

        # Notify both players that challenge is accepted
        fire_and_forget(
            sio.emit(
                "challenge_accepted",
                {"session": session_data},
                to=f"user:{ch.challenger_id}",
            )
        )
        fire_and_forget(
            sio.emit(
                "challenge_accepted",
                {"session": session_data},
                to=f"user:{ch.opponent_id}",
            )
        )

        # Broadcast initial game state to the game room
        state = {
            "session_id": session.id,
            "label": ch.label,
            "size": size,
            "tiles": [None] * size,
            "turn_user_id": ch.challenger_id,
            "scores": {"p1": 0, "p2": 0},
            "reveal_all_until": reveal_ms,
        }
        fire_and_forget(sio.emit("game_state", state, to=f"game:{session.id}"))

        # ======================================================
        # ✅ Return session info to REST API client
        # ======================================================
        return Response(session_data, status=201)


# -----------------------------
# 1️⃣  Challenge: create
# -----------------------------
from rest_framework import generics, permissions
from .models import GameChallenge
from .serializers import ChallengeCreateSerializer
from .constants import LABEL_SIZES

class ChallengeCreateView(generics.CreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChallengeCreateSerializer

    def perform_create(self, serializer):
        challenger = self.request.user
        opponent = serializer.validated_data["opponent"]
        label = serializer.validated_data["label"]

        if label not in LABEL_SIZES:
            raise ValueError("Invalid label")

        serializer.save(challenger=challenger, status="pending")



# -----------------------------
# 2️⃣  Challenge: list pending
# -----------------------------
from rest_framework import generics, permissions
from django.db import models
from .models import GameChallenge
from .serializers import ChallengeSerializer

class PendingChallengesView(generics.ListAPIView):
    """
    Shows all pending challenges for the logged-in user (both sent and received).
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChallengeSerializer

    def get_queryset(self):
        user = self.request.user
        return GameChallenge.objects.filter(status="pending").filter(
            models.Q(challenger=user) | models.Q(opponent=user)
        )


# -----------------------------
# 4️⃣  My active session
# -----------------------------
from rest_framework import views, permissions, status
from rest_framework.response import Response
from django.db import models
from .models import GameSession
from .serializers import SessionSerializer

class MyActiveSessionView(views.APIView):
    """
    Returns the current active game session for the logged-in user, if any.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        session = (
            GameSession.objects.filter(status="active")
            .filter(models.Q(player1=request.user) | models.Q(player2=request.user))
            .order_by("-started_at")
            .first()
        )

        if not session:
            return Response({"active": False})

        return Response({
            "active": True,
            "session": SessionSerializer(session).data
        })


# -----------------------------
# 5️⃣  Game state view
# -----------------------------
from rest_framework import views, permissions, status
from rest_framework.response import Response
from django_redis import get_redis_connection
from .models import GameSession

r = get_redis_connection("default")

class SessionStateView(views.APIView):
    """
    Returns the current board, revealed tiles, scores, and turn info for this session.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        try:
            session = GameSession.objects.get(pk=pk)
        except GameSession.DoesNotExist:
            return Response({"detail": "Session not found."}, status=404)

        # Security check — only players in this game can see it
        if request.user.id not in (session.player1_id, session.player2_id):
            return Response({"detail": "Forbidden."}, status=403)

        # Redis keys
        keys = {
            "board": f"game:{pk}:board",
            "revealed": f"game:{pk}:revealed",
            "turn": f"game:{pk}:turn",
            "scores": f"game:{pk}:scores",
            "meta": f"game:{pk}:meta",
        }

        # Fetch board and state from Redis
        meta = r.hgetall(keys["meta"])
        if not meta:
            return Response({"detail": "Game data not found in Redis."}, status=404)

        size = int(meta[b"size"])
        label = int(meta[b"label"])
        board = [int(x) for x in r.lrange(keys["board"], 0, -1)]
        revealed = {int(i) for i in r.smembers(keys["revealed"])}
        scores = {k.decode(): int(v) for k, v in r.hgetall(keys["scores"]).items()}
        turn = int(r.get(keys["turn"]))
        reveal_all_until = int(meta.get(b"reveal_all_until", b"0"))

        # Hide unrevealed tiles
        tiles = [(board[i] if i in revealed else None) for i in range(size)]

        data = {
            "session_id": pk,
            "label": label,
            "size": size,
            "tiles": tiles,
            "turn_user_id": turn,
            "scores": scores,
            "reveal_all_until": reveal_all_until,
            "status": session.status,
        }

        return Response(data)


# -----------------------------
# 6️⃣  Flip (play turn)
# -----------------------------
from rest_framework import views, permissions, status
from rest_framework.response import Response
from django.utils import timezone
from django.db import transaction
from django_redis import get_redis_connection

from .models import GameSession
from .sockets import sio
from .utils import fire_and_forget

r = get_redis_connection("default")


class FlipView(views.APIView):
    """
    Handle a player's turn: flip two tiles, check for match, update scores, and broadcast updates.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        indices = request.data.get("indices", [])
        if not (isinstance(indices, list) and len(indices) == 2):
            return Response({"detail": "Provide exactly two indices."}, status=400)

        i, j = int(indices[0]), int(indices[1])
        if i == j:
            return Response({"detail": "Pick two different tiles."}, status=400)

        try:
            sess = GameSession.objects.select_for_update().get(pk=pk)
        except GameSession.DoesNotExist:
            return Response({"detail": "Session not found."}, status=404)

        uid = request.user.id
        if uid not in (sess.player1_id, sess.player2_id):
            return Response({"detail": "Forbidden"}, status=403)

        keys = {
            "board": f"game:{pk}:board",
            "revealed": f"game:{pk}:revealed",
            "turn": f"game:{pk}:turn",
            "scores": f"game:{pk}:scores",
            "meta": f"game:{pk}:meta",
        }

        turn_raw = r.get(keys["turn"])
        if not turn_raw:
            return Response({"detail": "Game state missing or expired."}, status=400)
        turn = int(turn_raw)
        if uid != turn:
            return Response({"detail": "Not your turn."}, status=409)

        size = int(r.hget(keys["meta"], "size"))
        if not (0 <= i < size and 0 <= j < size):
            return Response({"detail": "Out of bounds."}, status=400)

        revealed = {int(x) for x in r.smembers(keys["revealed"])}
        if i in revealed or j in revealed:
            return Response({"detail": "Tile already matched."}, status=400)

        board = [int(x) for x in r.lrange(keys["board"], 0, -1)]
        match = board[i] == board[j]

        # --- Update Redis state ---
        if match:
            r.sadd(keys["revealed"], i, j)
            role = "p1" if uid == sess.player1_id else "p2"
            r.hincrby(keys["scores"], role, 1)

        new_revealed = r.scard(keys["revealed"])
        finished = new_revealed == size

        # --- Handle end of game ---
        if finished:
            scores = {k.decode(): int(v) for k, v in r.hgetall(keys["scores"]).items()}
            sess.p1_score = scores.get("p1", 0)
            sess.p2_score = scores.get("p2", 0)
            if sess.p1_score > sess.p2_score:
                sess.winner_id = sess.player1_id
            elif sess.p2_score > sess.p1_score:
                sess.winner_id = sess.player2_id
            sess.status = "finished"
            sess.ended_at = timezone.now()
            sess.save()
        else:
            # Switch turn
            next_uid = sess.player2_id if uid == sess.player1_id else sess.player1_id
            r.set(keys["turn"], next_uid)

        # --- Prepare response payload ---
        payload = {
            "session_id": pk,
            "matched": match,
            "indices": [i, j],
            "image_ids": [board[i], board[j]],
            "next_turn_user_id": None if finished else (
                sess.player2_id if uid == sess.player1_id else sess.player1_id
            ),
            "finished": finished,
        }

        # --- 🔔 Broadcast live updates to both players ---
        fire_and_forget(sio.emit("game_move", payload, to=f"game:{pk}"))

        state = {
            "session_id": pk,
            "label": sess.label,
            "size": size,
            "tiles": [
                board[x] if x in {int(v) for v in r.smembers(keys["revealed"])} else None
                for x in range(size)
            ],
            "turn_user_id": None if finished else payload["next_turn_user_id"],
            "scores": {k.decode(): int(v) for k, v in r.hgetall(keys["scores"]).items()},
            "reveal_all_until": int(r.hget(keys["meta"], "reveal_all_until") or 0),
        }
        fire_and_forget(sio.emit("game_state", state, to=f"game:{pk}"))

        return Response(payload)
