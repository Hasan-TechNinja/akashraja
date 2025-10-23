from django.conf import settings
from django.db import models
from django.utils.crypto import get_random_string

User = settings.AUTH_USER_MODEL

def generate_player_id():
    # e.g., 123-456-789
    raw = get_random_string(9, allowed_chars="0123456789")
    return f"{raw[:3]}-{raw[3:6]}-{raw[6:]}"

class UserProfile(models.Model):
    user = models.OneToOneField(User, related_name="profile", on_delete=models.CASCADE)
    player_id = models.CharField(max_length=20, unique=True, default=generate_player_id)
    name = models.CharField(max_length=100, blank=True, null=True)
    image = models.ImageField(upload_to="profiles/", blank=True, null=True)
    avatar = models.URLField(blank=True, null=True)  # or ImageField if you manage uploads
    online = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username} ({self.player_id})"


class Friendship(models.Model):
    """Undirected friendship (store smaller user id first to enforce uniqueness)."""
    user_a = models.ForeignKey(User, on_delete=models.CASCADE, related_name="friendships_a")
    user_b = models.ForeignKey(User, on_delete=models.CASCADE, related_name="friendships_b")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = (("user_a", "user_b"),)

    def save(self, *args, **kwargs):
        # normalize ordering so user_a.id < user_b.id
        if self.user_a_id and self.user_b_id and self.user_a_id > self.user_b_id:
            self.user_a, self.user_b = self.user_b, self.user_a
        super().save(*args, **kwargs)


class FriendRequest(models.Model):
    from_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_requests")
    to_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="received_requests")
    created_at = models.DateTimeField(auto_now_add=True)
    accepted = models.BooleanField(default=False)

    class Meta:
        unique_together = (("from_user", "to_user"),)


class LastPlayed(models.Model):
    """Pairs of users who recently played together (dedup per day)."""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="last_played")
    with_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="last_played_with")
    at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["user", "-at"])]
        unique_together = ("user", "with_user")  # ensures 1 entry per pair
