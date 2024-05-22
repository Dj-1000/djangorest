from rest_framework import serializers
from snippet.models import Snippet,LANGUAGE_CHOICES,STYLE_CHOICES
from django.contrib.auth.models import User

  
class UserSerializer(serializers.HyperlinkedModelSerializer):
    snippets = serializers.HyperlinkedRelatedField(many=True, view_name='snippet-detail', read_only=True)

    class Meta:
        model = User
        fields = ['url', 'id', 'username', 'snippets']
        
        
        
class SnippetSerializer(serializers.ModelSerializer):
    created_by = UserSerializer()
    class Meta:
        model = Snippet
        fields = ['id','url','title', 'code', 'linenos', 'language', 'style','created_by']
    
    def update(self, instance, validated_data):
        instance.title = validated_data.get('title', instance.title)
        instance.code = validated_data.get('code', instance.code)
        instance.linenos = validated_data.get('linenos', instance.linenos)
        instance.language = validated_data.get('language', instance.language)
        instance.style = validated_data.get('style', instance.style)
        instance.save()
        return instance
    

        
      