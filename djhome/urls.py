from django.contrib import admin
from django.urls import path,include
import rest_framework.urls
from snippet.views import UserList,DetailUser
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from rest_framework.urlpatterns import format_suffix_patterns


urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('admin/', admin.site.urls),
    path('snippets/',include('snippet.urls')),
    path('auth-urls',include('rest_framework.urls')),
    path('user/',UserList.as_view(),name='user-list'),
    path('user/<int:pk>/',DetailUser.as_view(),name='user-detail'),
]
