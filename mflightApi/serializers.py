from rest_framework import serializers
from django.contrib.auth.models import User                         
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
User._meta.get_field('email')._unique = True

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']
    def validateEmail( self,email ):                            #validating email format. must contains @ and .
        try:                                                    #cannot start with special characters.
            validate_email( email )
            return email
        except ValidationError:
            return False
    
    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User.objects.create_user(**validated_data)           
        user.set_password(password)  
        user.save()                              
        return user