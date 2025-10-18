from django.contrib.auth import get_user_model
from .models import Friendship

User = get_user_model()

def are_friends(u1, u2):
    a, b = sorted([u1.id, u2.id])
    return Friendship.objects.filter(user_a_id=a, user_b_id=b).exists()
