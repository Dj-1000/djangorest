from rest_framework import permissions
from .models import Snippet

class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """
    message = "This user is restricted to the this view"
    # def has_permission(self, request, view):
    #     if request.method==permissions.SAFE_METHODS:
    #         return True
    #     # Write permissions are only allowed to the owner of the snippet.
    #     return request.user == obj.created_by
        
    #     return super().has_permission(request, view)
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        print("OBJTYPE: ",type(obj))
        if request.method==permissions.SAFE_METHODS:
            return True
        # Write permissions are only allowed to the owner of the snippet.
        return request.user == obj.created_by