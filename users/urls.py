from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views
from django.urls import path, re_path, reverse_lazy
from rest_framework_simplejwt.views import (TokenObtainPairView,
                                            TokenRefreshView)

from .views import (CustomTokenVerifyView,
                    LoginView, RegisterView, UserAPIView)

app_name = 'users'

urlpatterns = [
       path("register/", RegisterView.as_view(), name="create-user"),
       path('login/', LoginView.as_view()),
       path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
       path("token/verify/", CustomTokenVerifyView.as_view(), name="token-refresh"),
       path("me/", UserAPIView.as_view(), name="user-info"),
     
]
