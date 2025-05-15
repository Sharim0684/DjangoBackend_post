from django.urls import path
from .views import (
    SignupAPIView,
    LoginAPIView,
    PersonViewSet,
    health_check,
    SocialLoginView,
    AutoLoginView,
    PlatformSelectionView,
    CheckCredentialsView,
    CreatePostView,
    OAuthCallbackView
)
from .views import UserPlatformsView
from . import views

urlpatterns = [
    # Existing authentication endpoints
    path('signup/', SignupAPIView.as_view(), name='signup'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('health/', health_check, name='health-check'),
    
    # OAuth2 Authorization endpoints
    path('auth/facebook/authorize/', views.facebook_authorize, name='facebook_authorize'),
   # path('auth/linkedin/authorize/', views.linkedin_authorize, name='linkedin_authorize'),
    
    # OAuth2 Callback endpoints
    path('auth/facebook/callback/', OAuthCallbackView.as_view(), name='facebook_callback'),
    path('auth/linkedin/callback/', OAuthCallbackView.as_view(), name='linkedin_callback'),
    
    # Social Login endpoints
    path('auth/facebook/login/', SocialLoginView.as_view(), name='facebook-login'),
    path('auth/linkedin/login/', SocialLoginView.as_view(), name='linkedin-login'),
    path('auth/instagram/login/', SocialLoginView.as_view(), name='instagram-login'),  # Add this line
    
    # Platform management endpoints
    path('user-platforms/', UserPlatformsView.as_view(), name='user-platforms'),
    path('platforms/', PlatformSelectionView.as_view(), name='platform-selection'),
    path('auth/check-credentials/', CheckCredentialsView.as_view(), name='check-credentials'),
    
    # Social media posting endpoint
    path('social/post/', CreatePostView.as_view(), name='social_post'),
    
    # Person endpoints
    path('person/', PersonViewSet.as_view({'get': 'list', 'post': 'create'}), name='person-list'),
    path('person/<int:pk>/', PersonViewSet.as_view({
        'get': 'retrieve',
        'put': 'update',
        'patch': 'partial_update',
        'delete': 'destroy'
    }), name='person-detail'),
    
    # Auto-login endpoint
    path('auth/auto-login/', AutoLoginView.as_view(), name='auto-login'),
]


