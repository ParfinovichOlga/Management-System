"""
Views for the user API.
"""
from rest_framework import generics
from user.serializers import UserSerializer
from rest_framework_simplejwt.authentication import JWTAuthentication
from core.permissions import IsAnonymous, ProfileOwner


class CreateUserView(generics.CreateAPIView):
    """Create a new user in the system."""
    serializer_class = UserSerializer
    permission_classes = [IsAnonymous]


class ManageUserView(generics.RetrieveUpdateDestroyAPIView):
    """Manage the authenticated user."""
    serializer_class = UserSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [ProfileOwner]

    def get_object(self):
        """Retrieve and return the authenticated user."""
        user = self.request.user
        self.check_object_permissions(self.request, user)
        return user
