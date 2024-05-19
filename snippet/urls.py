from django.urls import path
from .views import (
    SnippetList,
    SnippetDetail,
    SnippetCreate,
    api_root,
    SnippetHighlight
)
from rest_framework.urlpatterns import format_suffix_patterns


urlpatterns = format_suffix_patterns([
    path('',api_root),
    path('list/', SnippetList.as_view(),name='snippet-list'),
    path('post/',SnippetCreate.as_view()),
    path('add/',SnippetList.as_view()),
    path('list/<int:pk>/', SnippetDetail.as_view(),name='snippet-detail'),
    path('delete/<int:pk>/',SnippetDetail.as_view()),
    path('update/<int:pk>/',SnippetDetail.as_view()),
    path("<int:pk>/highlight/",SnippetHighlight.as_view(),name='snippet-highlight'),

])