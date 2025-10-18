from django.contrib.auth import get_user_model
from django.db.models import Q
from rest_framework import status, generics, mixins
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes

from .models import UserProfile, Friendship, FriendRequest, LastPlayed
from .serializers import (
    UserMiniSerializer, FriendSerializer, FriendRequestSerializer, LastPlayedSerializer, UserProfileSerializer
)
from .permissions import IsAuthenticated
from .utils import are_friends

User = get_user_model()


class MeView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        return Response(UserMiniSerializer(request.user).data)


class FriendsListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = FriendSerializer

    def get_queryset(self):
        u = self.request.user
        return Friendship.objects.filter(Q(user_a=u) | Q(user_b=u)).order_by("-created_at")


class AddFriendByPlayerIDView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        player_id = request.data.get("player_id", "").strip()
        if not player_id:
            return Response({"detail": "player_id required"}, status=400)

        try:
            to_profile = UserProfile.objects.select_related("user").get(player_id=player_id)
        except UserProfile.DoesNotExist:
            return Response({"detail": "Player not found"}, status=404)

        if to_profile.user_id == request.user.id:
            return Response({"detail": "Cannot add yourself."}, status=400)

        if are_friends(request.user, to_profile.user):
            return Response({"detail": "Already friends."}, status=200)

        fr, created = FriendRequest.objects.get_or_create(
            from_user=request.user, to_user=to_profile.user
        )
        if not created:
            return Response({"detail": "Request already sent."}, status=200)

        return Response(FriendRequestSerializer(fr).data, status=201)


class RespondFriendRequestView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, pk):
        accept = bool(request.data.get("accept"))
        try:
            fr = FriendRequest.objects.get(pk=pk, to_user=request.user, accepted=False)
        except FriendRequest.DoesNotExist:
            return Response({"detail": "Request not found"}, status=404)

        if accept:
            # create friendship
            Friendship.objects.create(user_a=fr.from_user, user_b=fr.to_user)
            fr.accepted = True
            fr.save(update_fields=["accepted"])
            return Response({"detail": "Friend added"}, status=200)
        else:
            fr.delete()
            return Response({"detail": "Request declined"}, status=200)


class RemoveFriendView(APIView):
    permission_classes = [IsAuthenticated]
    def delete(self, request, user_id):
        a, b = sorted([request.user.id, int(user_id)])
        deleted, _ = Friendship.objects.filter(user_a_id=a, user_b_id=b).delete()
        if deleted:
            return Response(status=204)
        return Response({"detail": "Not friends"}, status=404)


class SearchUsersView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserMiniSerializer

    def get_queryset(self):
        q = self.request.query_params.get("q", "").strip()
        users = User.objects.all().select_related("profile")
        if q:
            users = users.filter(Q(username__icontains=q) | Q(profile__player_id__icontains=q))
        return users.order_by("username")[:20]


class LastPlayedListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = LastPlayedSerializer

    def get_queryset(self):
        return LastPlayed.objects.filter(user=self.request.user).select_related("with_user__profile").order_by("-at")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def record_last_played(request):
    """Call this from game server to record that two users played together."""
    other_id = request.data.get("with_user_id")
    if not other_id:
        return Response({"detail": "with_user_id required"}, status=400)
    if int(other_id) == request.user.id:
        return Response({"detail": "invalid"}, status=400)
    LastPlayed.objects.create(user_id=request.user.id, with_user_id=other_id)
    LastPlayed.objects.create(user_id=other_id, with_user_id=request.user.id)
    return Response({"ok": True})


class UserProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserProfileSerializer

    def get_object(self):
        profile, created = UserProfile.objects.get_or_create(user=self.request.user)
        return profile