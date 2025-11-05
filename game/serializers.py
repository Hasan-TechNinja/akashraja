# game/serializers.py
from rest_framework import serializers
from .models import GameChallenge, GameSession


class SessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = GameSession
        fields = ("id","player1","player2","label","status","started_at","ended_at","p1_score","p2_score","winner_id")


class ChallengeSerializer(serializers.ModelSerializer):
    class Meta:
        model = GameChallenge
        fields = "__all__"


class ChallengeCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = GameChallenge
        fields = ["opponent", "label"]
