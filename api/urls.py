from django.urls import path
from .views import (
    SignupAPIView,
    LoginAPIView,
    PersonViewSet,
    health_check,
    SocialLoginView
)

urlpatterns = [
    path('signup/', SignupAPIView.as_view(), name='signup'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('health/', health_check, name='health-check'),
    
    # Social Authentication URLs
    # Social Authentication URLs
    path('auth/facebook/login/', SocialLoginView.as_view(), name='facebook-login'),
    path('auth/instagram/login/', SocialLoginView.as_view(), name='instagram-login'),
    path('auth/linkedin/login/', SocialLoginView.as_view(), name='linkedin-login'),
    
    # Person URLs
    path('person/', PersonViewSet.as_view({'get': 'list', 'post': 'create'}), name='person-list'),
    path('person/<int:pk>/', PersonViewSet.as_view({
        'get': 'retrieve',
        'put': 'update',
        'patch': 'partial_update',
        'delete': 'destroy'
    }), name='person-detail'),
]

