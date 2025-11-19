# game/serializers.py
from rest_framework import serializers
from .models import GameChallenge, GameSession


class SessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = GameSession
        fields = ("id","player1","player2","label","category","status", "started_at","ended_at","p1_score","p2_score","winner_id")


class ChallengeSerializer(serializers.ModelSerializer):
    challenger_device_id = serializers.SerializerMethodField()
    challenger_name = serializers.SerializerMethodField()

    class Meta:
        model = GameChallenge
        fields = "__all__"

    def get_challenger_device_id(self, obj):
        profile = getattr(obj.challenger, "profile", None)
        return getattr(profile, "device_id", None)

    def get_challenger_name(self, obj):
        profile = getattr(obj.challenger, "profile", None)
        return getattr(profile, "name", None)




class ChallengeCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = GameChallenge
        fields = ["opponent", "label", "category"]

