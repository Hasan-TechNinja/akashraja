from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import permissions
from home.serializers import AddAlbumImagesSerializer, AlbumImageSerializer, AlbumSerializer, OptionSerializer, CategorySerializer
from . models import Album, AlbumImage, Option, Category

# Create your views here.

class CategoryView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        categories = Category.objects.all()
        serializer = CategorySerializer(categories, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class OptionView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, category_id):
        options = Option.objects.filter(category_id=category_id)
        serializer = OptionSerializer(options, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class AlbumView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        albums = Album.objects.filter(user=request.user)
        serializer = AlbumSerializer(albums, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        title = request.data.get('title')
        images = request.FILES.getlist('images')

        if not title:
            return Response({'error': 'Title is required.'}, status=status.HTTP_400_BAD_REQUEST)
        if not images:
            return Response({'error': 'At least one image is required.'}, status=status.HTTP_400_BAD_REQUEST)

        album = Album.objects.create(user=request.user, title=title)
        for img in images:
            AlbumImage.objects.create(album=album, image=img)

        serializer = AlbumSerializer(album)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    

class AlbumDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, album_id):
        try:
            album = Album.objects.get(id=album_id, user=request.user)
        except Album.DoesNotExist:
            return Response({'error': 'Album not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = AlbumSerializer(album)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

    def delete(self, request, album_id):
        try:
            album = Album.objects.get(id=album_id, user=request.user)
        except Album.DoesNotExist:
            return Response({'error': 'Album not found.'}, status=status.HTTP_404_NOT_FOUND)

        album.delete()
        return Response({'message': 'Album deleted successfully.'}, status=status.HTTP_200_OK)
    

    def put(self, request, album_id):
        try:
            album = Album.objects.get(id=album_id, user=request.user)
        except Album.DoesNotExist:
            return Response({'error': 'Album not found.'}, status=status.HTTP_404_NOT_FOUND)

        title = request.data.get('title')
        images = request.FILES.getlist('images')

        if title:
            album.title = title
            album.save()

        if images:
            for img in images:
                AlbumImage.objects.create(album=album, image=img)

        serializer = AlbumSerializer(album)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class AlbumImageAudioView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, image_id):
        try:
            image = AlbumImage.objects.get(id=image_id, album__user=request.user)
        except AlbumImage.DoesNotExist:
            return Response({'error': 'Image not found or not owned by this user.'}, status=status.HTTP_404_NOT_FOUND)

        audio = request.FILES.get('audio')

        if not audio:
            return Response({'error': 'Audio file is required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Replace or add the audio file
        image.audio = audio
        image.save()

        serializer = AlbumImageSerializer(image)
        return Response(serializer.data, status=status.HTTP_200_OK)

class AddImagesToAlbumView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = AddAlbumImagesSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Images added successfully!"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)