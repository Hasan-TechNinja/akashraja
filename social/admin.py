from django.contrib import admin
from . models import UserProfile

# Register your models here.

class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'player_id', 'name', 'online')
    search_fields = ('user__username', 'player_id', 'name') 

admin.site.register(UserProfile, UserProfileAdmin)