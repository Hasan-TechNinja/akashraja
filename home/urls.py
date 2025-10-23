from django.urls import path
from . import views

urlpatterns = [
    path('categories/', views.CategoryView.as_view(), name='category-list'),
    path('categories/<int:category_id>/options/', views.OptionView.as_view(), name='category-options'),
    path('albums/', views.AlbumView.as_view(), name='albums'),
    path('albums/<int:album_id>/', views.AlbumDetailView.as_view(), name='album-detail'),

    # path('albums/<int:album_id>/', views.AlbumDetailView.as_view(), name='album-detail'),
    path('album-images/<int:image_id>/audio/', views.AlbumImageAudioView.as_view(), name='album-image-audio'),
    path('albums/add-images/', views.AddImagesToAlbumView.as_view(), name='add-images-to-album'),

]