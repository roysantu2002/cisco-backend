"""
URL configuration for backend project.

"""
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from django.contrib import admin
from django.urls import path
from django.urls import path, re_path, include
# Import your WebSocket consumers
from scripts.consumers import ScriptConsumer


websocket_urlpatterns = [
    re_path(r'ws/scripts/(?P<script_room>\w+)/$', ScriptConsumer.as_asgi()),
]

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/schema/', SpectacularAPIView.as_view(), name='api-schema'),
    path('api/scripts/', include('scripts.urls')),  # Include the 'scripts.urls' here
    path(
        'api/docs/',
        SpectacularSwaggerView.as_view(url_name='api-schema'),
        name='api-docs',
    ),
]

