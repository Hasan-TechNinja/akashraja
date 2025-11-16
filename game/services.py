from django.db import transaction
from django_redis import get_redis_connection
from .models import GameChallenge, GameSession
from .serializers import SessionSerializer
from .constants import LABEL_SIZES, IMAGE_IDS
import random
import time
from django.utils import timezone

r = get_redis_connection("default")

def handle_create_challenge(challenger_id, opponent_id, label):
    """Create a new challenge."""
    challenge = GameChallenge.objects.create(
        challenger_id=challenger_id,
        opponent_id=opponent_id,
        label=label,
        status="pending",
    )
    return challenge

def handle_respond_challenge(challenge_id, accept, user_id):
    """Respond to a challenge and optionally create a session."""
    with transaction.atomic():
        challenge = GameChallenge.objects.select_for_update().get(pk=challenge_id)
        if challenge.opponent_id != user_id:
            raise ValueError("Not authorized to respond to this challenge.")
        if challenge.status != "pending":
            raise ValueError("Challenge already handled.")

        challenge.status = "accepted" if accept else "declined"
        challenge.save()

        if not accept:
            return None, None

        session = GameSession.objects.create(
            player1=challenge.challenger,
            player2=challenge.opponent,
            label=challenge.label,
        )

        keys = _session_keys(session.id)
        size = LABEL_SIZES[challenge.label]
        images = random.sample(IMAGE_IDS, size // 2)
        board = images + images
        random.shuffle(board)

        r.delete(keys["board"], keys["revealed"])
        r.rpush(keys["board"], *board)
        r.delete(keys["revealed"])
        r.hset(keys["scores"], mapping={"p1": 0, "p2": 0})
        r.set(keys["turn"], challenge.challenger_id)
        reveal_ms = int((time.time() + 2.0) * 1000)
        r.hset(
            keys["meta"],
            mapping={
                "label": challenge.label,
                "size": size,
                "player1": challenge.challenger_id,
                "player2": challenge.opponent_id,
                "reveal_all_until": reveal_ms,
            },
        )

        state = {
            "session_id": session.id,
            "label": challenge.label,
            "size": size,
            "tiles": [None] * size,
            "turn_user_id": challenge.challenger_id,
            "scores": {"p1": 0, "p2": 0},
            "reveal_all_until": reveal_ms,
        }

        return session, state

def handle_flip(session_id, user_id, i, j):
    """Handle a tile flip."""
    keys = _session_keys(session_id)

    turn_raw = r.get(keys["turn"])
    if not turn_raw:
        raise ValueError("Game state missing or expired.")
    turn = int(turn_raw)
    if user_id != turn:
        raise ValueError("Not your turn.")

    size = int(r.hget(keys["meta"], "size"))
    if not (0 <= i < size and 0 <= j < size):
        raise ValueError("Out of bounds.")

    revealed = {int(x) for x in r.smembers(keys["revealed"])}
    if i in revealed or j in revealed:
        raise ValueError("Tile already matched.")

    board = [int(x) for x in r.lrange(keys["board"], 0, -1)]
    match = board[i] == board[j]

    if match:
        r.sadd(keys["revealed"], i, j)
        role = "p1" if user_id == int(r.hget(keys["meta"], "player1")) else "p2"
        r.hincrby(keys["scores"], role, 1)

    new_revealed = r.scard(keys["revealed"])
    finished = new_revealed == size

    if finished:
        scores = {k.decode(): int(v) for k, v in r.hgetall(keys["scores"]).items()}
        session = GameSession.objects.get(pk=session_id)
        session.p1_score = scores.get("p1", 0)
        session.p2_score = scores.get("p2", 0)
        if session.p1_score > session.p2_score:
            session.winner_id = session.player1_id
        elif session.p2_score > session.p1_score:
            session.winner_id = session.player2_id
        session.status = "finished"
        session.ended_at = timezone.now()
        session.save()
    else:
        next_uid = int(r.hget(keys["meta"], "player2")) if user_id == int(r.hget(keys["meta"], "player1")) else int(r.hget(keys["meta"], "player1"))
        r.set(keys["turn"], next_uid)

    payload = {
        "session_id": session_id,
        "matched": match,
        "indices": [i, j],
        "image_ids": [board[i], board[j]],
        "next_turn_user_id": None if finished else next_uid,
        "finished": finished,
    }

    state = {
        "session_id": session_id,
        "label": int(r.hget(keys["meta"], "label")),
        "size": size,
        "tiles": [
            board[x] if x in {int(v) for v in r.smembers(keys["revealed"])} else None
            for x in range(size)
        ],
        "turn_user_id": None if finished else payload["next_turn_user_id"],
        "scores": {k.decode(): int(v) for k, v in r.hgetall(keys["scores"]).items()},
        "reveal_all_until": int(r.hget(keys["meta"], "reveal_all_until") or 0),
    }

    return payload, state

def _session_keys(sid):
    base = f"game:{sid}:"
    return {
        "board": base + "board",
        "revealed": base + "revealed",
        "turn": base + "turn",
        "scores": base + "scores",
        "meta": base + "meta",
    }