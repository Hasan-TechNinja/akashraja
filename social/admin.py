from django.contrib import admin
from . models import UserProfile, Friendship, FriendRequest, LastPlayed

# Register your models here.

class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'player_id', 'name', 'online')
    search_fields = ('user__username', 'player_id', 'name') 

admin.site.register(UserProfile, UserProfileAdmin)


class FriendshipAdmin(admin.ModelAdmin):
    list_display = ('id', 'user_a', 'user_b', 'created_at')
    search_fields = ('user_a__username', 'user_b__username')
admin.site.register(Friendship, FriendshipAdmin)


class FriendRequestAdmin(admin.ModelAdmin):
    list_display = ('id', 'from_user', 'to_user', 'accepted', 'created_at')
    search_fields = ('from_user__username', 'to_user__username')
admin.site.register(FriendRequest, FriendRequestAdmin)


class LastPlayedAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'with_user', 'at')
    search_fields = ('user__username', 'with_user__username')
admin.site.register(LastPlayed, LastPlayedAdmin)