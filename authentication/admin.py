from django.contrib import admin
from .models import Profile

# Register your models here.

class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'name', 'phone')
    search_fields = ('user__username', 'name', 'phone') 

admin.site.register(Profile, ProfileAdmin)