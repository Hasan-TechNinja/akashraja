from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import UserProfile, Friendship, FriendRequest, LastPlayed

User = get_user_model()

class UserMiniSerializer(serializers.ModelSerializer):
    avatar = serializers.CharField(source="profile.avatar", read_only=True)
    online = serializers.BooleanField(source="profile.online", read_only=True)
    player_id = serializers.CharField(source="profile.player_id", read_only=True)

    class Meta:
        model = User
        fields = ("id", "username", "player_id", "avatar", "online")


class FriendSerializer(serializers.ModelSerializer):
    friend = serializers.SerializerMethodField()
    created_at = serializers.DateTimeField(read_only=True)

    class Meta:
        model = Friendship
        fields = ("id", "friend", "created_at")

    def get_friend(self, obj):
        request_user = self.context["request"].user
        other = obj.user_b if obj.user_a_id == request_user.id else obj.user_a
        return UserMiniSerializer(other).data


class FriendRequestSerializer(serializers.ModelSerializer):
    from_user = UserMiniSerializer(read_only=True)
    to_user = UserMiniSerializer(read_only=True)

    class Meta:
        model = FriendRequest
        fields = ("id", "from_user", "to_user", "accepted", "created_at")


class LastPlayedSerializer(serializers.ModelSerializer):
    with_user = UserMiniSerializer()

    class Meta:
        model = LastPlayed
        fields = ("id", "with_user", "at")

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['player_id', 'name', 'image', 'avatar', 'online']