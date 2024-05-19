from rest_framework import serializers
from snippet.models import Snippet,LANGUAGE_CHOICES,STYLE_CHOICES
from django.contrib.auth.models import User

  
class SnippetSerializer(serializers.ModelSerializer):
    highlight = serializers.HyperlinkedIdentityField(view_name='snippet-highlight', format='html')
    created_by = serializers.ReadOnlyField(source='created_by.username')
    class Meta:
        model = Snippet
        fields = ['id','url','highlight','title', 'code', 'linenos', 'language', 'style','created_by']
    
    def create(self,validated_data):
        user = self.context.get("user")
        validated_data["created_by"] = user
        return Snippet.objects.create(**validated_data)
    
    def update(self, instance, validated_data):
        instance.title = validated_data.get('title', instance.title)
        instance.code = validated_data.get('code', instance.code)
        instance.linenos = validated_data.get('linenos', instance.linenos)
        instance.language = validated_data.get('language', instance.language)
        instance.style = validated_data.get('style', instance.style)
        instance.save()
        return instance
    
class UserSerializer(serializers.HyperlinkedModelSerializer):
    snippets = serializers.HyperlinkedRelatedField(many=True, view_name='snippet-detail', read_only=True)

    class Meta:
        model = User
        fields = ['url', 'id', 'username', 'snippets']
        
      