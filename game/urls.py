from django.urls import path
from . import views

urlpatterns = [
    # 🎯 Challenge management
    path("challenges/", views.ChallengeCreateView.as_view(), name="create-challenge"),
    path("challenges/pending/", views.PendingChallengesView.as_view(), name="pending-challenges"),
    path("challenges/<int:pk>/respond/", views.ChallengeRespondView.as_view(), name="respond-challenge"),

    # 🎮 Game sessions
    path("sessions/my/active/", views.MyActiveSessionView.as_view(), name="my-active-session"),
    path("sessions/<int:pk>/state/", views.SessionStateView.as_view(), name="session-state"),
    path("sessions/<int:pk>/flip/", views.FlipView.as_view(), name="flip-tiles"),
]
