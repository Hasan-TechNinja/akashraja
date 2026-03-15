from django.db import transaction
from django_redis import get_redis_connection
from .models import GameChallenge, GameSession
from .serializers import SessionSerializer
from .constants import LABEL_SIZES, IMAGE_IDS
import random
import time
from django.utils import timezone
from home.models import Option


r = get_redis_connection("default")

def fetch_images_for_category(category_id, size):
    options = Option.objects.filter(category_id=category_id)

    needed = size // 2
    if options.count() < needed:
        raise ValueError("Not enough images in this category")

    ids = list(options.values_list("id", flat=True))
    return random.sample(ids, needed)


def handle_create_challenge(challenger_id, opponent_id, label, category):
    challenge = GameChallenge.objects.create(
        challenger_id=challenger_id,
        opponent_id=opponent_id,
        label=label,
        category_id=category,      # ✅ NEW
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
            category=challenge.category,    # ✅ ADDED
        )

        keys = _session_keys(session.id)
        size = LABEL_SIZES[challenge.label]
        images = fetch_images_for_category(challenge.category_id, size)
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
                "category": challenge.category_id,     # ✅ NEW
                "reveal_all_until": reveal_ms,
            },
        )

        state = {
            "session_id": session.id,
            "label": challenge.label,
            "size": size,
            "tiles": [],
            "turn_user_id": challenge.challenger_id,
            "scores": {"p1": 0, "p2": 0},
            "reveal_all_until": reveal_ms,
        }

        return session, state

# def handle_flip(session_id, user_id, i, j):
#     """Handle a tile flip."""
#     keys = _session_keys(session_id)

#     if i < 0 or j < 0 or not (0 <= i < size and 0 <= j < size):
#         player1 = int(r.hget(keys["meta"], "player1"))
#         player2 = int(r.hget(keys["meta"], "player2"))

#         next_uid = player2 if user_id == player1 else player1
#         r.set(keys["turn"], next_uid)

#     turn_raw = r.get(keys["turn"])
#     if not turn_raw:
#         raise ValueError("Game state missing or expired.")
#     turn = int(turn_raw)
#     if user_id != turn:
#         raise ValueError("Not your turn.")

#     size = int(r.hget(keys["meta"], "size"))
#     if not (0 <= i < size and 0 <= j < size):
#         raise ValueError("Out of bounds.")

#     revealed = {int(x) for x in r.smembers(keys["revealed"])}
#     if i in revealed or j in revealed:
#         raise ValueError("Tile already matched.")

#     board = [int(x) for x in r.lrange(keys["board"], 0, -1)]
#     match = board[i] == board[j]

#     if match:
#         r.sadd(keys["revealed"], i, j)
#         role = "p1" if user_id == int(r.hget(keys["meta"], "player1")) else "p2"
#         r.hincrby(keys["scores"], role, 1)
#     else:
#         role = "p1" if user_id == int(r.hget(keys["meta"], "player1")) else "p2"
#         r.hincrby(keys["scores"], f"{role}_miss", 1)


#     # Recompute revealed and finished
#     revealed = {int(x) for x in r.smembers(keys["revealed"])}
#     new_revealed = len(revealed)
#     finished = new_revealed == size

#     # Common state pieces (read before we delete anything)
#     meta = r.hgetall(keys["meta"])
#     label = int(meta[b"label"])
#     reveal_all_until = int(meta.get(b"reveal_all_until", b"0") or 0)
#     scores = {k.decode(): int(v) for k, v in r.hgetall(keys["scores"]).items()}
#     # tiles = [board[x] if x in revealed else None for x in range(size)]
#     # INDEX-BASED TILE REPRESENTATION FOR FINAL STATE
#     if len(revealed) == 0:
#         tiles = []
#     else:
#         tiles = [
#             (i if i in revealed else None)
#             for i in range(size)
#         ]



#     if finished:
#         # Persist final scores + winner
#         session = GameSession.objects.select_for_update().get(pk=session_id)
#         session.p1_score = scores.get("p1", 0)
#         session.p2_score = scores.get("p2", 0)
#         if session.p1_score > session.p2_score:
#             session.winner_id = session.player1_id
#         elif session.p2_score > session.p1_score:
#             session.winner_id = session.player2_id
#         else:
#             session.winner_id = None
#         session.status = "finished"
#         session.ended_at = timezone.now()
#         session.save()

#         # Build final state & results for frontend
#         state = {
#             "session_id": session_id,
#             "label": label,
#             "size": size,
#             "tiles": tiles,
#             "turn_user_id": None,
#             "scores": scores,
#             "reveal_all_until": reveal_all_until,
#         }

#         results = {
#             "session_id": session_id,
#             "winner": session.winner_id,
#             "scores": scores,
#         }

#         payload = {
#             "event": "game_end",
#             "results": results,
#         }

#         # Optional: clean Redis now that game is done
#         for k in keys.values():
#             r.delete(k)

#         return payload, state

#     # -----------------------
#     # Non-final move branch
#     # -----------------------
#     next_uid = (
#         int(r.hget(keys["meta"], "player2"))
#         if user_id == int(r.hget(keys["meta"], "player1"))
#         else int(r.hget(keys["meta"], "player1"))
#     )
#     r.set(keys["turn"], next_uid)

#     payload = {
#         "session_id": session_id,
#         "matched": match,
#         "indices": [i, j],
#         "image_ids": [board[i], board[j]],
#         "next_turn_user_id": next_uid,
#         "finished": False,
#     }

#     state = {
#         "session_id": session_id,
#         "label": label,
#         "size": size,
#         "tiles": tiles,
#         "turn_user_id": next_uid,
#         "scores": scores,
#         "reveal_all_until": reveal_all_until,
#     }

#     return payload, state

def handle_flip(session_id, user_id, i, j):
    """Handle a tile flip, including invalid index skips."""
    keys = _session_keys(session_id)

    # Whose turn?
    turn_raw = r.get(keys["turn"])
    if not turn_raw:
        raise ValueError("Game state missing or expired.")
    turn = int(turn_raw)
    if user_id != turn:
        raise ValueError("Not your turn.")

    # Board size
    size = int(r.hget(keys["meta"], "size"))

    # ---------------------------------------------------
    # INVALID INDICES → SKIP TURN + MISS COUNT
    # ---------------------------------------------------
    if i < 0 or j < 0 or not (0 <= i < size and 0 <= j < size):
        player1 = int(r.hget(keys["meta"], "player1"))
        player2 = int(r.hget(keys["meta"], "player2"))

        role = "p1" if user_id == player1 else "p2"

        # Count miss for invalid move
        r.hincrby(keys["scores"], f"{role}_miss", 1)

        # Switch turn
        next_uid = player2 if user_id == player1 else player1
        r.set(keys["turn"], next_uid)

        # Build state
        meta = r.hgetall(keys["meta"])
        label = int(meta[b"label"])
        reveal_all_until = int(meta.get(b"reveal_all_until", b"0") or 0)

        revealed = {int(x) for x in r.smembers(keys["revealed"])}
        scores = {k.decode(): int(v) for k, v in r.hgetall(keys["scores"]).items()}

        if len(revealed) == 0:
            tiles = []
        else:
            tiles = [
                (idx if idx in revealed else None) for idx in range(size)
            ]

        state = {
            "session_id": session_id,
            "label": label,
            "size": size,
            "tiles": tiles,
            "turn_user_id": next_uid,
            "scores": scores,
            "reveal_all_until": reveal_all_until,
        }

        payload = {
            "session_id": session_id,
            "event": "skip_turn",
            "reason": "invalid_index",
            "sent_indices": [i, j],
            "next_turn_user_id": next_uid,
        }

        return payload, state

    # ---------------------------------------------------
    # VALID INDICES → NORMAL MATCH/MISS LOGIC
    # ---------------------------------------------------
    revealed = {int(x) for x in r.smembers(keys["revealed"])}
    if i in revealed or j in revealed:
        raise ValueError("Tile already matched.")

    board = [int(x) for x in r.lrange(keys["board"], 0, -1)]
    match = board[i] == board[j]

    # scoring
    player1 = int(r.hget(keys["meta"], "player1"))
    role = "p1" if user_id == player1 else "p2"

    if match:
        r.sadd(keys["revealed"], i, j)
        r.hincrby(keys["scores"], role, 1)
    else:
        r.hincrby(keys["scores"], f"{role}_miss", 1)

    # Recalculate revealed tiles
    revealed = {int(x) for x in r.smembers(keys["revealed"])}
    finished = len(revealed) == size

    # Common state
    meta = r.hgetall(keys["meta"])
    label = int(meta[b"label"])
    reveal_all_until = int(meta.get(b"reveal_all_until", b"0") or 0)
    scores = {k.decode(): int(v) for k, v in r.hgetall(keys["scores"]).items()}

    if len(revealed) == 0:
        tiles = []
    else:
        tiles = [
            (idx if idx in revealed else None)
            for idx in range(size)
        ]

    # ---------------------------------------------------
    # FINISH GAME
    # ---------------------------------------------------
    if finished:
        with transaction.atomic():
            session = GameSession.objects.select_for_update().get(pk=session_id)
            session.p1_score = scores.get("p1", 0)
            session.p2_score = scores.get("p2", 0)

            if session.p1_score > session.p2_score:
                session.winner_id = session.player1_id
            elif session.p2_score > session.p1_score:
                session.winner_id = session.player2_id
            else:
                session.winner_id = None

            session.status = "finished"
            session.ended_at = timezone.now()
            session.save()

        state = {
            "session_id": session_id,
            "label": label,
            "size": size,
            "tiles": tiles,
            "turn_user_id": None,
            "scores": scores,
            "reveal_all_until": reveal_all_until,
        }

        payload = {
            "event": "game_end",
            "results": {
                "session_id": session_id,
                "winner": session.winner_id,
                "scores": scores,
            },
        }

        # Cleanup
        for k in keys.values():
            r.delete(k)

        return payload, state

    # ---------------------------------------------------
    # NORMAL MOVE → SWITCH TURN
    # ---------------------------------------------------
    player2 = int(r.hget(keys["meta"], "player2"))
    next_uid = player2 if user_id == player1 else player1
    r.set(keys["turn"], next_uid)

    payload = {
        "session_id": session_id,
        "matched": match,
        "indices": [i, j],
        "image_ids": [board[i], board[j]],
        "next_turn_user_id": next_uid,
        "finished": False,
    }

    state = {
        "session_id": session_id,
        "label": label,
        "size": size,
        "tiles": tiles,
        "turn_user_id": next_uid,
        "scores": scores,
        "reveal_all_until": reveal_all_until,
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

def _finalize_game(session_id):
    keys = _session_keys(session_id)

    # Load scores with user IDs (correct shape)
    scores = {k.decode(): int(v) for k, v in r.hgetall(keys["scores"]).items()}

    if scores:
        max_score = max(scores.values())
        winner_ids = [int(uid) for uid, sc in scores.items() if sc == max_score]
        winner = winner_ids[0] if len(winner_ids) == 1 else None
    else:
        winner = None

    # Persist to DB
    with transaction.atomic():
        sess = GameSession.objects.select_for_update().get(pk=session_id)
        sess.ended_at = timezone.now()
        sess.winner_id = winner
        sess.status = "completed"
        sess.save()

    # Delete Redis keys
    for k in keys.values():
        r.delete(k)

    return {
        "winner": winner,
        "scores": scores,
        "session_id": session_id,
    }
