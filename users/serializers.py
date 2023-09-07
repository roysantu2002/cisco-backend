"""
Selializers for the user account View.
"""
import logging
import os
import sys

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core import exceptions
from django.shortcuts import get_object_or_404
from rest_framework import permissions, serializers, status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework_simplejwt.serializers import (TokenObtainPairSerializer,
                                                  TokenRefreshSerializer)
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Image, Profile, User

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)
    class Meta:
        model = User
        fields = ['email', 'password']

    def create(self, validated_data):
        validated_data.pop('password', None)  # Remove password from validated data
        return super().create(validated_data)

class UserRegisterationSerializer(serializers.ModelSerializer):
    """
    Serializer class to serialize registration requests and create a new user.
    """

    class Meta:
        model = User
        fields = ('email', 'password')
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

    # def create(self, validated_data):
    #     print(validated_data)
    #     return User.objects.create_user(**validated_data)

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super(MyTokenObtainPairSerializer, cls).get_token(user)
        token['email'] = user.email
        return token

# class CustomUserSerializer(serializers.ModelSerializer):
#     """
#     Serializer class to serialize CustomUser model.
#     """
#
#     class Meta:
#         model = User
#         fields = ('email', 'password', 'is_staff', 'is_admin')

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'customer', 'role', 'is_staff', 'is_admin')
        extra_kwargs = {"password": {"write_only": True}}

    # def validate(self, attrs):
    #     data = super().validate(attrs)
    #     # refresh = self.get_token(self.user)
    #     # data['lifetime'] = int(refresh.access_token.lifetime.total_seconds())
    #     return data

class TokenObtainLifetimeSerializer(TokenObtainPairSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        access_token = refresh.access_token
        data['lifetime'] = int(refresh.access_token.lifetime.total_seconds())
        return data


class TokenRefreshLifetimeSerializer(TokenRefreshSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = RefreshToken(attrs['refresh'])
        data['lifetime'] = int(refresh.access_token.lifetime.total_seconds())
        return data

class UserLoginSerializer(serializers.Serializer):
    """
    Serializer class to authenticate users with email and password.
    """
    class Meta:
        model = User
        fields = ('email', 'is_staff')

    email = serializers.CharField()
    password = serializers.CharField(write_only=True)
    print('iiiiiiii')
    def validate(self, data):
        user = authenticate(**data)
        if user and user.is_active:
            return user
        raise serializers.ValidationError("Incorrect Credentials")

class ProfileSerializer(UserSerializer):
    """
    Serializer class to serialize the user Profile model
    """

    class Meta:
        model = Profile
        fields = ("bio",)

class ProfileAvatarSerializer(serializers.ModelSerializer):
    """
    Serializer class to serialize the avatar
    """

    class Meta:
        model = Profile
        fields = ("bio", "avatar",)

class LoginSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('pk', 'email', 'customer', 'role', 'is_staff', 'is_admin')


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        try:
            if email and password:
                user = authenticate(email=email, password=password)

                if not user:
                    return Response({'error': 'User account is disabled.'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                raise serializers.ValidationError('Email and password are required')

            is_superuser = user.is_superuser
            is_staff = user.is_staff
            is_admin = user.is_admin

            refresh = RefreshToken.for_user(user)
            access = str(refresh.access_token)
            role = 'guest'
            print(user.role)
            if is_superuser or is_admin and user.role == 2:
                role = 'admin'

            if user.role == 1:
                role = 'user'

            if user.role == 3:
                role = 'seller'

            return {
                'id': user.pk,
                'role': role,
                'customer': user.customer,
                'email': email,
                'accessToken': str(access),
                'refreshToken': str(refresh),
            }
        except Exception as e:
                return Response({'error': 'Invalid login credentials.'}, status=status.HTTP_400_BAD_REQUEST)

#image
class ImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Image
        fields = ('image',)

    def create(self, validated_data):
        return Image.objects.create(image=validated_data['image'])

class ProfileAvatarSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ('avatar', 'bio')

        def update(self, instance, validated_data):
            user_profile = self.context['user_profile']
            instance.avatar = validated_data.get('avatar', instance.avatar)
            instance.bio = validated_data.get('bio', instance.bio)
            instance.save()
            return user_profile
        
class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ('bio', 'avatar')

####

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
 
    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
            return user
        except User.DoesNotExist:
            raise ValidationError({'error': 'User with this email address does not exist.'})

    def save(self):
        user = self.validated_data['email']
        user.set_unusable_password()
        user.save()
        return user
