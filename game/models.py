# game/models.py
from django.conf import settings
from django.db import models

class GameChallenge(models.Model):
    CHALLENGE_STATUS = (
        ("pending","pending"),
        ("accepted","accepted"),
        ("declined","declined"),
        ("expired","expired")
    )

    challenger = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="challenges_sent", on_delete=models.CASCADE)
    opponent   = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="challenges_received", on_delete=models.CASCADE)
    label      = models.PositiveSmallIntegerField()
    category   = models.ForeignKey("home.Category", on_delete=models.CASCADE, blank=True, null=True)
    status     = models.CharField(max_length=10, choices=CHALLENGE_STATUS, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)


class GameSession(models.Model):
    STATUS = (("active","active"),("finished","finished"),("aborted","aborted"))
    player1   = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="games_as_p1", on_delete=models.CASCADE)
    player2   = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="games_as_p2", on_delete=models.CASCADE)
    label     = models.PositiveSmallIntegerField()
    category = models.ForeignKey("home.Category", on_delete=models.CASCADE, blank=True, null=True)
    status    = models.CharField(max_length=10, choices=STATUS, default="active")
    started_at= models.DateTimeField(auto_now_add=True)
    ended_at  = models.DateTimeField(null=True, blank=True)
    # final scores (ephemeral scores live in Redis during play)
    p1_score  = models.PositiveSmallIntegerField(default=0)
    p2_score  = models.PositiveSmallIntegerField(default=0)
    winner_id = models.IntegerField(null=True, blank=True)  # store user id of winner or None for draw
