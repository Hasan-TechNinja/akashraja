from django.urls import path
from .views import (
    MeView, FriendsListView, AddFriendByPlayerIDView, RespondFriendRequestView,
    RemoveFriendView, SearchUsersView, LastPlayedListView, record_last_played
)
from .views import UserProfileView

urlpatterns = [
    path("me/", MeView.as_view()),
    path("friends/", FriendsListView.as_view()),
    path("friends/add/", AddFriendByPlayerIDView.as_view()),
    path("friends/requests/<int:pk>/respond/", RespondFriendRequestView.as_view()),
    path("friends/<int:user_id>/", RemoveFriendView.as_view()),
    path("search/", SearchUsersView.as_view()),
    path("last-played/", LastPlayedListView.as_view()),
    path("last-played/record/", record_last_played),
    path("profile/", UserProfileView.as_view()),
]
