import logging
import random
import string
import urllib.parse
from urllib.parse import unquote, urljoin

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.hashers import make_password
from django.contrib.auth.tokens import (PasswordResetTokenGenerator,
                                        default_token_generator)
from django.contrib.sessions.models import Session
from django.core.mail import send_mail
from django.http import (HttpResponse, HttpResponseBadRequest,
                         HttpResponseNotFound)
from django.shortcuts import render
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import generics, status
from rest_framework.generics import GenericAPIView, RetrieveUpdateAPIView
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.settings import api_settings
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.views import TokenVerifyView, TokenViewBase
from django.conf import settings

from .models import Profile, User
from .serializers import (ImageSerializer, PasswordResetSerializer,
                          ProfileAvatarSerializer, ProfileSerializer,
                          TokenObtainLifetimeSerializer,
                          TokenRefreshLifetimeSerializer,
                          UserRegisterationSerializer, UserSerializer)



# Use the logger in your code
# Get the logger instance for the views.py module
logger = logging.getLogger(__name__)

class RegisterView(GenericAPIView):
    """
    An endpoint for the client to create a new User.
    """

    permission_classes = [AllowAny]
    serializer_class = UserRegisterationSerializer

    def post(self, request):
        try:
            data = request.data
            email = data['email']
            password = data['password']

            if len(password) >= 8:
                if not User.objects.filter(email=email).exists():
                    try:
                        serializer = self.get_serializer(data=request.data)
                        if serializer.is_valid():
                            user = serializer.save()
                            # Logging user object for debugging purposes
                            logging.info(f"New user created: {user}")
                    except Exception as e:
                        logging.error(f"User registration error: {str(e)}")
                        return Response(
                            {'error': 'Something went wrong'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR
                        )
                    if User.objects.filter(email=email).exists():
                        return Response(
                            {'success': 'account-created'},
                            status=status.HTTP_201_CREATED
                        )
                    else:
                        return Response(
                            {'error': 'Something went wrong'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR
                        )
                else:
                    return Response(
                        {'error': 'email-already-in-use'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                return Response(
                    {'error': 'Password must be at least 8 characters'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        except Exception as e:
            logging.error(f"User registration error: {str(e)}")
            return Response(
                {'error': 'Something went wrong when trying to register account'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# --------------RegisterView

class UserAPIView(RetrieveUpdateAPIView):
    """
    Get, Update user information
    """

    permission_classes = [IsAuthenticated]
    # serializer_class = UserSerializer

    def get(self, request):
        try:
            profile = Profile.objects.get(user=request.user)
            # avatar = profile.avatar if profile.avatar else None
            return Response({
                'avatar': profile.avatar if profile.avatar else None,
                'first_name': profile.first_name,
                'last_name': profile.last_name,
                'address': profile.address,
                'bio': profile.bio,
                'mobile': profile.mobile,
            })
        except Exception as e:
            logger.error(f"User information retrieval error: {str(e)}")
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# -----UserAPIView


class BlacklistTokenUpdateView(generics.GenericAPIView):
    authentication_classes = ()

    def post(self, request=None):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            logging.error(f"Token blacklisting error: {str(e)}")
            return Response(status=status.HTTP_400_BAD_REQUEST)


class TokenObtainPairView(TokenViewBase):
    """
    Return JWT tokens (access and refresh) for specific user based on username and password.
    """
    serializer_class = TokenObtainLifetimeSerializer


class TokenRefreshView(TokenViewBase):
    """
    Renew tokens (access and refresh) with new expire time based on specific user's access token.
    """
    serializer_class = TokenRefreshLifetimeSerializer
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES


class UserProfileAPIView(RetrieveUpdateAPIView):
    """
    Get, Update user profile
    """

    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        return self.request.user.profile


class UserAvatarAPIView(RetrieveUpdateAPIView):
    """
    Get, Update user avatar
    """

    queryset = Profile.objects.all()
    serializer_class = ProfileAvatarSerializer
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        return self.request.user.profile


class LoginView(APIView):
    permission_classes = [AllowAny,]
    serializer_class = UserRegisterationSerializer

    def post(self, request, format=None):
        data = request.data
        email = data.get('email', None)
        password = data.get('password', None)

        try:
            if email and password:
                user = authenticate(email=email, password=password)
                if not user:
                    # Invalid credentials
                    return Response({'error': 'Wrong credentials.'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                # Missing email or password
                return Response({'error': 'Wrong credentials.'}, status=status.HTTP_400_BAD_REQUEST)

            if user.is_active:
                serializer = UserRegisterationSerializer(user)
                is_superuser = user.is_superuser
                is_admin = user.is_admin

                refresh = RefreshToken.for_user(user)
                access = str(refresh.access_token)
                role = 'guest'

                # Retrieve profile information
                profile = Profile.objects.get(user=user)

                if is_superuser or is_admin and user.role == 2:
                    role = 'admin'
                if user.role == 1:
                    role = 'user'

                return Response({
                    'id': user.pk,
                    'role': role,
                    'email': email,
                    'accessToken': str(access),
                    'refreshToken': str(refresh),
                })
        except Exception as e:
            # Log any error that occurs during login
            logger.error(f"Login error: {str(e)}")
            return Response({'error': 'Wrong credentials.'}, status=status.HTTP_400_BAD_REQUEST)

# --------LoginView




class GetImageURL(GenericAPIView):
    permission_classes = [AllowAny,]

    def get(self, request, *args, **kwargs):
        image_name = kwargs.get('image_name')
        media_url = settings.MEDIA_URL
        image_url = urljoin(media_url, image_name)
        return Response({'image_url': image_url})



# CustomTokenVerifyView
class CustomTokenVerifyView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        access_token = request.data['token']

        if access_token:
            try:
                token = AccessToken(access_token)
                token.verify()
                user_id = token['user_id']

                if user_id is not None:
                    # Check if the user is active
                    user = get_user_model().objects.get(id=user_id)
                    if user.is_active:
                        return Response(status=200)
            except (TokenError, InvalidToken):
                pass
            except get_user_model().DoesNotExist:
                pass

        return Response(status=400)


token_verify = TokenVerifyView.as_view()
