from django.contrib.auth import get_user_model
from django.db.models import Q
from rest_framework import status, generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes

from .models import UserProfile, Friendship, FriendRequest, LastPlayed
from .serializers import UserInfoByPlayerIDSerializer, UserMiniSerializer, FriendSerializer, FriendRequestSerializer, LastPlayedSerializer, UserProfileSerializer, UserSerializer, DeviceIDSerializer
from .permissions import IsAuthenticated
from .utils import are_friends
from django.db.models import Q
from django.utils import timezone


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
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        player_id = request.data.get("player_id")

        if not player_id:
            return Response({"detail": "player_id is required."}, status=400)

        # ✅ 1. Find target user by player_id
        try:
            target_profile = UserProfile.objects.get(player_id=player_id)
            try:
                target_user_device_id = target_profile.device_id
            except UserProfile.DoesNotExist:
                target_user_device_id = None

            target_user = target_profile.user
        except UserProfile.DoesNotExist:
            return Response({"detail": "User not found with this player_id."}, status=404)

        current_user = request.user

        # ✅ 2. Prevent self-request
        if target_user == current_user:
            return Response({"detail": "You cannot send a friend request to yourself."}, status=400)

        # ✅ 3. Check if already friends
        already_friends = Friendship.objects.filter(
            Q(user_a=current_user, user_b=target_user) |
            Q(user_a=target_user, user_b=current_user)
        ).exists()
        if already_friends:
            return Response({"detail": "You are already friends with this user."}, status=400)

        # ✅ 4. Check if friend request already sent (either direction)
        existing_request = FriendRequest.objects.filter(
            Q(from_user=current_user, to_user=target_user) |
            Q(from_user=target_user, to_user=current_user)
        ).first()

        if existing_request:
            if existing_request.accepted:
                return Response({"detail": "You are already friends."}, status=400)
            elif existing_request.from_user == current_user:
                return Response({"detail": "You already sent a request to this user."}, status=400)
            else:
                return Response({"detail": "This user already sent you a request."}, status=400)

        # ✅ 5. Create new friend request
        FriendRequest.objects.create(from_user=current_user, to_user=target_user)
        return Response({"detail": f"{target_user_device_id}"}, status=201)
    


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
    """Record that two users played together (update or create latest record)."""
    other_id = request.data.get("with_user_id")
    if not other_id:
        return Response({"detail": "with_user_id required"}, status=400)

    try:
        other_id = int(other_id)
    except ValueError:
        return Response({"detail": "Invalid user id"}, status=400)

    if other_id == request.user.id:
        return Response({"detail": "invalid"}, status=400)

    user_id = request.user.id

    # Use update_or_create to keep only one entry per pair
    LastPlayed.objects.update_or_create(
        user_id=user_id,
        with_user_id=other_id,
        defaults={"at": timezone.now()},
    )
    LastPlayed.objects.update_or_create(
        user_id=other_id,
        with_user_id=user_id,
        defaults={"at": timezone.now()},
    )

    return Response({"ok": True})



class UserProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserProfileSerializer

    def get_object(self):
        profile, created = UserProfile.objects.get_or_create(user=self.request.user)
        return profile
    



# 1️⃣ Sent Friend Requests (I sent)
class SentFriendRequestsView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = FriendRequestSerializer

    def get_queryset(self):
        return FriendRequest.objects.filter(from_user=self.request.user, accepted=False)


# 2️⃣ Received Friend Requests (To me)
class ReceivedFriendRequestsView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = FriendRequestSerializer

    def get_queryset(self):
        return FriendRequest.objects.filter(to_user=self.request.user, accepted=False)


# 3️⃣ My Friends List
class MyFriendsListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_queryset(self):
        user = self.request.user
        # find all friendships where user is user_a or user_b
        friendships = Friendship.objects.filter(Q(user_a=user) | Q(user_b=user))
        # collect all other users
        friend_ids = [
            f.user_b_id if f.user_a_id == user.id else f.user_a_id
            for f in friendships
        ]
        return User.objects.filter(id__in=friend_ids)


class PlayedUsersListView(generics.ListAPIView):
    """
    Return the list of users that the authenticated user has played with.
    Each user appears only once with the last played time.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = LastPlayedSerializer

    def get_queryset(self):
        return (
            LastPlayed.objects.filter(user=self.request.user)
            .select_related("with_user__profile")
            .order_by("-at")
        )

class UpdateDeviceIDView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile, created = UserProfile.objects.get_or_create(user=request.user)
        serializer = DeviceIDSerializer(profile)
        return Response(serializer.data)

    
    def put(self, request):
        device_id = request.data.get("device_id", "").strip()
        if not device_id:
            return Response({"detail": "device_id is required."}, status=400)
        profile, created = UserProfile.objects.get_or_create(user=request.user)
        # allow partial update (only device_id)
        serializer = DeviceIDSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class UserInfoByPlayerID(APIView):
    def post(self, request):
        player_id = request.data.get('player_id')

        if not player_id:
            return Response({"error": "player_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        user_data = UserProfile.objects.filter(player_id=player_id).first()

        if not user_data:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserInfoByPlayerIDSerializer(user_data)

        return Response(serializer.data, status=status.HTTP_200_OK)