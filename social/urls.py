from django.urls import path
from .views import (
    MeView, FriendsListView, AddFriendByPlayerIDView, RespondFriendRequestView,
    RemoveFriendView, SearchUsersView, LastPlayedListView, record_last_played
)
from . import views

urlpatterns = [
    path("me/", MeView.as_view()),
    path("friends/", FriendsListView.as_view()),
    path("friends/add/", AddFriendByPlayerIDView.as_view()),
    path("friends/requests/<int:pk>/respond/", RespondFriendRequestView.as_view()),
    path("friends/<int:user_id>/", RemoveFriendView.as_view()),
    path("search/", SearchUsersView.as_view()),
    path("last-played/", LastPlayedListView.as_view()),
    path("last-played/record/", record_last_played),
    path("profile/", views.UserProfileView.as_view()),
    path("friends/requests/sent/", views.SentFriendRequestsView.as_view()),
    path("friends/requests/received/", views.ReceivedFriendRequestsView.as_view()),
    path("friends/my/", views.MyFriendsListView.as_view()),
    path("last-played/users/", views.PlayedUsersListView.as_view(), name="played-users-list"),
    path("profile/device-id/", views.UpdateDeviceIDView.as_view(), name="update-device-id"),
    path("user-data/by-playser-id/", views.UserInfoByPlayerID.as_view(), name='player-info'),

]
