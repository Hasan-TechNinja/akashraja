from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import permissions

# Create your views here.
class HomeView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        return Response({"message": "Welcome to the Home Page!"}, status=status.HTTP_200_OK)