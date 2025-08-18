"""Custom permissions for models."""
from rest_framework import permissions


class IsAnonymous(permissions.BasePermission):
    """Allow creating only unauthenticated user."""
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            return False
        return True


class ProfileOwner(permissions.BasePermission):
    """Allow changes only for owner."""
    def has_permission(self, request, view):
        return request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        """Allow retrieving and updating by owner except deleting"""
        return obj.id == request.user.id and request.method != 'DELETE'


class IsManagerOrReadOnly(permissions.BasePermission):
    """Allow changes for manager or read only"""
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        return bool(request.user and request.user.is_manager)


class IsAdminOrReadOnly(permissions.BasePermission):
    """Allow changes for admin or read only"""
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        return bool(request.user and request.user.is_staff)


class IsOwnerOrReadOnly(permissions.BasePermission):
    """Allow changes for owner or read only"""
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.user == request.user
