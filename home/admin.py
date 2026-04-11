from django.contrib import admin
from .models import Category, Option, Album

# Register your models here.

class CategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'name',)
    search_fields = ('name',)

admin.site.register(Category, CategoryAdmin)

class OptionAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'category')
    search_fields = ('name', 'category__name')
admin.site.register(Option, OptionAdmin)


class AlbumAdmin(admin.ModelAdmin):
    # Only use 'id' and 'user' since we know those exist
    list_display = ('id', 'user')
    search_fields = ('user__username',)

admin.site.register(Album, AlbumAdmin)