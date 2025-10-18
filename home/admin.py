from django.contrib import admin
from .models import Category, Option

# Register your models here.

class CategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'name',)
    search_fields = ('name',)

admin.site.register(Category, CategoryAdmin)

class OptionAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'category')
    search_fields = ('name', 'category__name')
admin.site.register(Option, OptionAdmin)