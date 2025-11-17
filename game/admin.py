from django.contrib import admin
from . models import GameChallenge, GameSession

# Register your models here.

class GameSessionAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'player1', 'player2', 'label', 'status', 'started_at', 'ended_at', 'p1_score', 'p2_score', 'winner_id'
    )
admin.site.register(GameSession, GameSessionAdmin)


class GameChallengeAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'challenger', 'opponent', 'label', 'status', 'created_at'
    )
admin.site.register(GameChallenge, GameChallengeAdmin)