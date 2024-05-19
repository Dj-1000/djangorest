from snippet.models import Snippet
from snippet.serializers import SnippetSerializer
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status,generics
from django.contrib.auth.models import User
from .serializers import UserSerializer
from rest_framework import permissions, renderers
from .permission import IsOwnerOrReadOnly
from rest_framework.decorators import api_view
from rest_framework.reverse import reverse
from utils.custom_exception import ValidationError


@api_view(['GET'])
def api_root(request, format=None):
    return Response({
        'users': reverse('user-list', request=request, format=format),
        'snippets': reverse('snippet-list', request=request, format=format)
    })
    
    
class SnippetList(APIView):
    permission_classes = [IsOwnerOrReadOnly]
    
    def get(self, request, format=None):
        snippets = Snippet.objects.all()
        self.check_object_permissions(request, snippets)
        serializer = SnippetSerializer(snippets, many=True,context = {"request":request})
        return Response(serializer.data)

    def post(self, request, format=None):
        print("REQUEST-USER :",request.user)
        serializer = SnippetSerializer(data=request.data,context={"user":request.user})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
class SnippetDetail(APIView):
    """
    Retrieve, update or delete a snippet instance.
    """
    permission_classes = (IsOwnerOrReadOnly,)
    def get_object(self, pk):
        try:
            return Snippet.objects.get(pk=pk)
        except Snippet.DoesNotExist:
            raise  ValidationError("Object does not exist")

    def get(self, request, pk, format=None):
        snippet = self.get_object(pk)
        self.check_object_permissions(request, snippet)
        serializer = SnippetSerializer(snippet,context={"request":request})
        return Response(serializer.data)

    def put(self, request, pk, format=None):
        snippet = self.get_object(pk)
        self.check_object_permissions(request, snippet)
        print("Update")
        serializer = SnippetSerializer(snippet, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        snippet = self.get_object(pk)
        self.check_object_permissions(request, snippet)
        snippet.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    
class SnippetCreate(generics.ListCreateAPIView):
    permission_classes = (IsOwnerOrReadOnly,)
    queryset = Snippet.objects.all()
    serializer_class = SnippetSerializer
    
class UserList(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class DetailUser(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    


class SnippetHighlight(generics.GenericAPIView):
    queryset = Snippet.objects.all()
    renderer_classes = [renderers.StaticHTMLRenderer]

    def get(self, request, *args, **kwargs):
        snippet = self.get_object()
        return Response(snippet.highlighted)