from .utils import fire_and_forget
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
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
from game.services import fetch_images_for_category



def _session_keys(sid):
    base = f"game:{sid}:"
    return {
        "board":   base + "board",
        "revealed": base + "revealed",
        "turn":     base + "turn",
        "scores":   base + "scores",
        "meta":     base + "meta",
    }


class ChallengeRespondView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        accept = bool(request.data.get("accept"))

        with transaction.atomic():
            try:
                ch = GameChallenge.objects.select_for_update().get(pk=pk)
            except GameChallenge.DoesNotExist:
                return Response({"detail": "Challenge not found"}, status=404)

            # ✅ Permission check
            if ch.opponent_id != request.user.id:
                return Response({"detail": "Not your challenge."}, status=403)

            if ch.status != "pending":
                return Response({"detail": "Already handled."}, status=400)

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
                category=ch.category,   # ✅ ADDED
            )


            # --- Initialize board in Redis ---
            keys = _session_keys(session.id)
            size = LABEL_SIZES[ch.label]
            # images = random.sample(IMAGE_IDS, size // 2)
            images = fetch_images_for_category(ch.category_id, size)
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
                    "category": ch.category_id,     # ✅ NEW
                    "reveal_all_until": reveal_ms,
                },
            )

        # --- Serialize session data ---
        session_data = SessionSerializer(session).data

        # ======================================================
        # 🔔 SOCKET.IO LIVE NOTIFICATIONS (fire-and-forget)
        # ======================================================

        # Notify both players that challenge is accepted
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f"user_{ch.challenger_id}",
            {"type": "challenge.accepted", "session": session_data},
        )
        async_to_sync(channel_layer.group_send)(
            f"user_{ch.opponent_id}",
            {"type": "challenge.accepted", "session": session_data},
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
        async_to_sync(channel_layer.group_send)(f"game_{session.id}", {"type": "game.state", "state": state})

        # ======================================================
        # ✅ Return session info to REST API client
        # ======================================================
        return Response(session_data, status=201)




class ChallengeCreateView(generics.CreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChallengeCreateSerializer

    def perform_create(self, serializer):
        challenger = self.request.user
        label = serializer.validated_data["label"]

        if label not in LABEL_SIZES:
            raise ValueError("Invalid label")

        serializer.save(
            challenger=challenger,
            status="pending"
        )





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



class MyActiveSessionView(views.APIView):
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

        # ------------------------------
        # 🔥 Fetch session state from Redis
        # ------------------------------

        pk = session.id
        keys = {
            "board": f"game:{pk}:board",
            "revealed": f"game:{pk}:revealed",
            "turn": f"game:{pk}:turn",
            "scores": f"game:{pk}:scores",
            "meta": f"game:{pk}:meta",
        }

        meta = r.hgetall(keys["meta"])
        if not meta:
            return Response({"active": True, "session": SessionSerializer(session).data})

        size = int(meta[b"size"])
        label = int(meta[b"label"])
        category = int(meta.get(b"category", b"0"))
        reveal_all_until = int(meta.get(b"reveal_all_until", b"0") or 0)

        board = [int(x) for x in r.lrange(keys["board"], 0, -1)]
        revealed = {int(i) for i in r.smembers(keys["revealed"])}
        scores = {k.decode(): int(v) for k, v in r.hgetall(keys["scores"]).items()}
        turn = int(r.get(keys["turn"]))

        # Same tile format as WebSocket:
        # if len(revealed) == 0:
        #     tiles = []
        # else:
        #     tiles = [(i if i in revealed else None) for i in range(size)]
        tiles = board   # show all image IDs


        # ------------------------------
        # 🎯 Return merged DB + Redis data
        # ------------------------------
        session_data = SessionSerializer(session).data
        session_data.update({
            "category": category,
            "size": size,
            "tiles": tiles,
            "turn_user_id": turn,
            "scores": scores,
            "reveal_all_until": reveal_all_until,
        })

        return Response({"active": True, "session": session_data})




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
        category = int(meta.get(b"category", 0))


        # Hide unrevealed tiles
        # tiles = [(board[i] if i in revealed else None) for i in range(size)]

        # Initial: no tiles revealed
        # if len(revealed) == 0:
        #     tiles = []
        # else:
        #     tiles = [
        #         (i if i in revealed else None)
        #         for i in range(size)
        #     ]
        tiles = board   # show all image IDs



        data = {
            "session_id": pk,
            "label": label,
            "category": category,
            "size": size,
            "tiles": tiles,
            "turn_user_id": turn,
            "scores": scores,
            "reveal_all_until": reveal_all_until,
            "status": session.status,
        }

        return Response(data)



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

        with transaction.atomic():
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
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(f"game_{pk}", {"type": "game.move", "payload": payload})

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
        async_to_sync(channel_layer.group_send)(f"game_{pk}", {"type": "game.state", "state": state})

        return Response(payload)
