from rest_framework import serializers
from django.contrib.auth.models import User
from . models import Album, AlbumImage, Category, Option


class OptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Option
        fields = ['id', 'name', 'image']


class CategorySerializer(serializers.ModelSerializer):
    options = OptionSerializer(many=True, read_only=True)

    class Meta:
        model = Category
        fields = ['id', 'name', 'image', 'options']


class AlbumImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlbumImage
        fields = ['id', 'image', 'audio', 'uploaded_at']



class AlbumSerializer(serializers.ModelSerializer):
    images = AlbumImageSerializer(many=True, read_only=True)

    class Meta:
        model = Album
        fields = ['id', 'title', 'created_at', 'images']


class AddAlbumImagesSerializer(serializers.Serializer):
    album_id = serializers.IntegerField()
    images = serializers.ListField(
        child=serializers.ImageField(),
        allow_empty=False
    )

    def create(self, validated_data):
        album_id = validated_data['album_id']
        images = validated_data['images']

        try:
            album = Album.objects.get(id=album_id)
        except Album.DoesNotExist:
            raise serializers.ValidationError("Album not found.")

        album_images = []
        for image in images:
            album_images.append(AlbumImage.objects.create(album=album, image=image))
        return album_images