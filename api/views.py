from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import viewsets, status, filters
from django.shortcuts import get_object_or_404, redirect
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from django.contrib.auth.hashers import check_password
from rest_framework.authentication import TokenAuthentication
import jwt
from datetime import datetime, timedelta
from django.conf import settings
from django.utils.timezone import now
from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import requests
import uuid
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from django.utils import timezone
from .authentication import MultiPlatformTokenAuthentication
from urllib.parse import urlencode


from .models import User, Person, SelectedPlatform, Credential # Changed from Credentials to Credential
from .serializers import SignupSerializer, PersonSerializer


class SignupAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token = jwt.encode(
                {"id": user.id,"email": user.email, "exp": datetime.utcnow() + timedelta(days=7)},
                settings.SECRET_KEY,
                algorithm="HS256",
            )
            return Response(
                {
                    "message": "Signup successful",
                    "userdata": {
                        "name": user.name,
                        "email": user.email,
                        "phone_number": user.phone_number,
                        "gender": user.gender,
                    },
                    "token": token,
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        if not email or not password:
            return Response(
                {"error": "Email and password are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"error": "Email does not exist."}, status=status.HTTP_400_BAD_REQUEST
            )

        if not check_password(password, user.password):
            return Response(
                {"error": "Incorrect password."}, status=status.HTTP_400_BAD_REQUEST
            )

        token = jwt.encode(
            {"id": user.id, "email": user.email, "exp": datetime.utcnow() + timedelta(days=7)},
            settings.SECRET_KEY,
            algorithm="HS256",
        )
        user.last_login = now()
        user.last_login_at = now()
        user.save()
        return Response(
            {
                "message": "Login successful",
                "userdata": {
                    "name": user.name,
                    "email": user.email,
                    "phone_number": user.phone_number,
                    "gender": user.gender,
                },
                "token": token,
            },
            status=status.HTTP_200_OK,
        )


class PersonViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated]  # Add this line
    queryset = Person.objects.all()
    serializer_class = PersonSerializer
    filter_backends = [filters.OrderingFilter, filters.SearchFilter]
    search_fields = ["name", "email", "age"]  # Allows searching by name or email
    ordering_fields = ["name", "age", "email"]  # Allows sorting by name, age, or email
    ordering = ["name"]  # Default ordering by name

    def create(self, request, *args, **kwargs):
        """
        Explicitly define required fields for request validation.
        """
        required_fields = ["name", "age", "email"]
        missing_fields = [
            field for field in required_fields if field not in request.data
        ]

        if missing_fields:
            return Response(
                {"error": f"Missing required fields: {', '.join(missing_fields)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return super().create(request, *args, **kwargs)

    def retrieve(self, request, pk=None):
        """
        Fetch a single Person by ID.
        """
        person = get_object_or_404(Person, pk=pk)
        serializer = self.get_serializer(person)
        return Response(serializer.data)

    def update(self, request, pk=None):
        """
        Fully updates a Person instance (PUT method).
        Requires all fields to be present in the request body.
        """
        person = get_object_or_404(Person, pk=pk)
        serializer = self.get_serializer(person, data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        """
        Partially updates a Person instance (PATCH method).
        Allows updating specific fields without sending the entire object.
        """
        person = get_object_or_404(Person, pk=pk)
        serializer = self.get_serializer(person, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        """
        Deletes a specific Person instance (DELETE method).
        """
        person = get_object_or_404(Person, pk=pk)
        person.delete()
        return Response(
            {"message": "Person deleted successfully"},
            status=status.HTTP_204_NO_CONTENT,
        )


@api_view(["GET"])
def health_check(request):
    """
    A simple API view to check if the API is up and running.
    """
    return Response({"status": "API is up and running!"})


class SocialLoginView(APIView):
    permission_classes = [AllowAny]

    def get_provider(self, request):
        # Extract provider from URL path
        path = request.path
        if 'facebook' in path:
            return 'facebook'
        elif 'instagram' in path:
            return 'instagram'
        elif 'linkedin' in path:
            return 'linkedin'
        return None

    def post(self, request, *args, **kwargs):
        provider = self.get_provider(request)
        if not provider:
            return Response({'error': 'Invalid provider'}, status=status.HTTP_400_BAD_REQUEST)

        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response({
                'error': 'Username and password are required'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Try to find user by email, phone number, or Instagram username
            try:
                if '@' in username:
                    user = User.objects.get(email=username)
                elif username.isdigit():
                    user = User.objects.get(phone_number=username)
                else:
                    # For Instagram/LinkedIn usernames
                    user = User.objects.get(name=username)
                
                # Update user if needed
                if not user.social_provider:
                    user.social_provider = provider
                    # Add temporary phone number if not exists
                    if not user.phone_number:
                        user.phone_number = f'temp_{str(uuid.uuid4())[:8]}'
                    user.save()
            except User.DoesNotExist:
                # Create new user
                if '@' in username:
                    # Email login
                    user = User.objects.create(
                        email=username,
                        username=username.split('@')[0],  # Set username from email
                        name=username.split('@')[0],
                        phone_number=f'temp_{str(uuid.uuid4())[:8]}',
                        gender=''
                    )
                elif username.isdigit():
                    # Phone number login
                    user = User.objects.create(
                        email=f'{username}@temp.com',
                        username=username,  # Use phone number as username
                        name=f'user_{username}',
                        phone_number=username,
                        gender=''
                    )
                else:
                    # Instagram username login
                    user = User.objects.create(
                        email=f'{username}@instagram.temp',
                        username=username,  # Use Instagram username
                        name=username,
                        phone_number=f'temp_{str(uuid.uuid4())[:8]}',
                        gender=''
                    )
                user.set_password(password)
                user.social_provider = provider
                user.save()

            # Remove JWT token generation and only use Token
            token, _ = Token.objects.get_or_create(user=user)
            # After creating/updating user, store credentials
            # In post method, after LinkedIn authentication
            linkedin_auth = self.authenticate_linkedin(username, password)
            if linkedin_auth['success']:
                Credential.objects.update_or_create(  # Changed from SocialMediaCredentials to Credential
                    user=user,
                    platform_name=provider,
                    defaults={
                        'username': username,
                        'password': linkedin_auth['access_token']  # Store OAuth token
                    }
                )
            
            return Response({
                'message': f'{provider.capitalize()} login successful',
                'userdata': {
                    'name': user.name,
                    'email': user.email,
                    'phone_number': user.phone_number,
                    'provider': provider
                },
                'token': token.key
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'error': f'Failed to process {provider} login: {str(e)}'
            }, status=status.HTTP_400_BAD_REQUEST)

    def authenticate_instagram(self, username, password):
        api_url = 'https://api.instagram.com/oauth/access_token'
        params = {
            'client_id': settings.INSTAGRAM_APP_ID,
            'client_secret': settings.INSTAGRAM_APP_SECRET,
            'username': username,
            'password': password,
            'grant_type': 'password'
        }
        response = requests.post(api_url, params=params)
        if response.status_code == 200:
            data = response.json()
            return {
                'success': True,
                'access_token': data.get('access_token')
            }
        return {'success': False}

    def authenticate_facebook(self, username, password):
        try:
            # Validate Facebook credentials
            graph = facebook.GraphAPI()
            auth_response = graph.get_app_access_token(
                settings.FACEBOOK_APP_ID,
                settings.FACEBOOK_APP_SECRET
            )
            return {
                'success': True,
                'access_token': auth_response
            }
        except Exception:
            return {'success': False}

    def authenticate_linkedin(self, username, password):
        try:
            # LinkedIn OAuth2 authentication using authorization code flow
            auth_url = 'https://www.linkedin.com/oauth/v2/accessToken'
            data = {
                'grant_type': 'authorization_code',
                'code': password,  # This should be the authorization code from LinkedIn
                'client_id': settings.LINKEDIN_CLIENT_ID,
                'client_secret': settings.LINKEDIN_CLIENT_SECRET,
                'redirect_uri': f'{settings.FRONTEND_URL}/auth/linkedin/callback'
            }
            response = requests.post(auth_url, data=data)
            if response.status_code == 200:
                return {
                    'success': True,
                    'access_token': response.json()['access_token']
                }
            return {'success': False}
        except Exception:
            return {'success': False}

    def get_auth_url(self, provider):
        configs = {
            'facebook': {
                'client_id': settings.FACEBOOK_APP_ID,
                'redirect_uri': f'{settings.FRONTEND_URL}/auth/facebook/callback',
                'scope': 'email'
            },
            'instagram': {
                'client_id': settings.INSTAGRAM_APP_ID,
                'redirect_uri': f'{settings.FRONTEND_URL}/auth/instagram/callback',
                'scope': 'basic'
            },
            'linkedin': {
                'client_id': settings.LINKEDIN_CLIENT_ID,
                'redirect_uri': f'{settings.FRONTEND_URL}/auth/linkedin/callback',
                'scope': 'openid profile w_member_social email'
            }
        }
        
        if provider in configs:
            config = configs[provider]
            if provider == 'instagram':
                return f'https://api.instagram.com/oauth/authorize?client_id={config["client_id"]}&redirect_uri={config["redirect_uri"]}&scope={config["scope"]}&response_type=code'
            elif provider == 'linkedin':
                return f'https://www.linkedin.com/oauth/v2/authorization?client_id={config["client_id"]}&redirect_uri={config["redirect_uri"]}&scope={config["scope"]}&response_type=code&state=random_state_string'
            elif provider == 'facebook':
                return f'https://www.facebook.com/v12.0/dialog/oauth?client_id={config["client_id"]}&redirect_uri={config["redirect_uri"]}&scope={config["scope"]}'


class AutoLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        provider = request.data.get('provider')
        if not provider:
            return Response({'error': 'Provider is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Get all users from database for the given provider
        users = User.objects.filter(social_provider=provider)
        
        if not users.exists():
            return Response({'error': f'No users found for provider {provider}'}, 
                          status=status.HTTP_404_NOT_FOUND)

        
        user = users.first()

        # Replace JWT with Token authentication
        token, _ = Token.objects.get_or_create(user=user)

        return Response({
            'message': f'{provider.capitalize()} auto-login successful',
            'userdata': {
                'name': user.name,
                'email': user.email,
                'phone_number': user.phone_number,
                'provider': provider
            },
            'token': token.key
        }, status=status.HTTP_200_OK)


class UserPlatformsView(APIView):
    authentication_classes = [MultiPlatformTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Get unique platform names from users
        platforms = User.objects.exclude(social_provider='').values_list('social_provider', flat=True).distinct()
        
        return Response({
            'platforms': list(platforms)
        }, status=status.HTTP_200_OK)


class PlatformSelectionView(APIView):
    authentication_classes = [MultiPlatformTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        #
        platforms = SelectedPlatform.objects.filter(user=request.user)
        
       
        user_provider = request.user.social_provider
       
        all_platforms = []
        
        if user_provider:
            platform_info = {
                'facebook': {'name': 'Facebook', 'key': 'facebook'},
                'linkedin': {'name': 'LinkedIn', 'key': 'linkedin'},
                'instagram': {'name': 'Instagram', 'key': 'instagram'},
                'twitter': {'name': 'Twitter', 'key': 'twitter'}
            }
            
            if user_provider in platform_info:
                platform = platform_info[user_provider].copy()
                platform['is_selected'] = platforms.filter(
                    platform=platform['key'], 
                    is_selected=True
                ).exists()
                all_platforms.append(platform)

        return Response({
            'platforms': all_platforms
        })

    def post(self, request):
        platform = request.data.get('platform')
        if not platform:
            return Response(
                {'error': 'Platform is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        is_selected = request.data.get('is_selected', False)

        # Verify that the platform matches user's social provider
        if platform != request.user.social_provider:
            return Response(
                {'error': 'You can only select the platform you logged in with'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update or create platform selection
        obj, created = SelectedPlatform.objects.update_or_create(
            user=request.user,
            platform=platform,
            defaults={'is_selected': is_selected}
        )

        return Response({
            'platform': obj.platform,
            'is_selected': obj.is_selected
        })


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Post, SelectedPlatform, SocialMediaCredentials  # Add SocialMediaCredentials here
from rest_framework.permissions import IsAuthenticated
import facebook
from datetime import datetime

class TokenManagementMixin:
    def get_valid_facebook_token(self, credentials):
        """Get a valid Facebook access token."""
        if not credentials.password:  # password field stores the access token
            return None
            
        # Check if token needs refresh (assuming expiry is stored in extra_data)
        try:
            expires_at = float(credentials.extra_data.get('expires_at', 0))
            if datetime.utcnow().timestamp() > expires_at - 600:
                new_token = self.exchange_for_long_lived_token(credentials.password)
                if new_token:
                    credentials.password = new_token
                    credentials.extra_data['expires_at'] = (datetime.utcnow() + timedelta(days=60)).timestamp()
                    credentials.save()
                    return new_token
                return None
            return credentials.password
        except (ValueError, AttributeError):
            return credentials.password

    def exchange_for_long_lived_token(self, short_lived_token):
        """Exchange a short-lived Facebook token for a long-lived one."""
        url = "https://graph.facebook.com/v22.0/oauth/access_token"
        params = {
            "grant_type": "fb_exchange_token",
            "client_id": settings.FACEBOOK_APP_ID,
            "client_secret": settings.FACEBOOK_APP_SECRET,
            "fb_exchange_token": short_lived_token,
        }
        response = requests.get(url, params=params)

        if response.status_code == 200:
            return response.json().get('access_token')
        return None

    def get_valid_linkedin_token(self, credentials):
        """Get a valid LinkedIn access token."""
        if not credentials.password:  # password field stores the access token
            return None

        try:
            expires_at = float(credentials.extra_data.get('expires_at', 0))
            if datetime.utcnow().timestamp() > expires_at - 600:
                new_token = self.refresh_linkedin_token(credentials.password)
                if new_token:
                    credentials.password = new_token
                    credentials.extra_data['expires_at'] = (datetime.utcnow() + timedelta(days=60)).timestamp()
                    credentials.save()
                    return new_token
            return credentials.password
        except (ValueError, AttributeError):
            return credentials.password

    def refresh_linkedin_token(self, current_token):
        """Refresh LinkedIn access token."""
        url = "https://www.linkedin.com/oauth/v2/accessToken"
        data = {
            "grant_type": "refresh_token",
            "client_id": settings.LINKEDIN_CLIENT_ID,
            "client_secret": settings.LINKEDIN_CLIENT_SECRET,
            "refresh_token": current_token
        }
        
        response = requests.post(url, data=data)
        
        if response.status_code == 200:
            return response.json().get('access_token')
        return None

# class CreatePostView(APIView):
#     authentication_classes = [MultiPlatformTokenAuthentication]
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         content = request.data.get('content', '')
#         enable_likes = request.data.get('enable_likes', True)
#         enable_comments = request.data.get('enable_comments', True)
#         media_file = request.FILES.get('media')

#         try:
#             # Create post instance
#             post = Post.objects.create(
#                 user=request.user,
#                 content=content,
#                 media=media_file,
#                 is_published=False,
#                 enable_likes=enable_likes,
#                 enable_comments=enable_comments
#             )

#             errors = []
#             is_published = False

#             # Get selected platforms
#             selected_platforms = SelectedPlatform.objects.filter(
#                 user=request.user,
#                 is_selected=True
#             )

#             for platform in selected_platforms:
#                 try:
#                     credentials = Credential.objects.get(
#                         user=request.user,
#                         platform_name=platform.platform
#                     )

#                     if platform.platform == 'facebook':
#                         # Facebook posting logic
#                         graph = facebook.GraphAPI(access_token=credentials.access_token)
                        
#                         if media_file:
#                             with open(post.media.path, 'rb') as image:
#                                 response = graph.put_photo(
#                                     image=image,
#                                     message=content
#                                 )
#                                 if response and 'id' in response:
#                                     is_published = True
#                                 else:
#                                     errors.append("Failed to post to Facebook")
#                         else:
#                             response = graph.put_object(
#                                 parent_object='me',
#                                 connection_name='feed',
#                                 message=content
#                             )
#                             if response and 'id' in response:
#                                 is_published = True
#                             else:
#                                 errors.append("Failed to post to Facebook")

#                     elif platform.platform == 'linkedin':
#                         # LinkedIn posting logic
#                         headers = {
#                             'Authorization': f'Bearer {credentials.access_token}',
#                             'Content-Type': 'application/json',
#                             'X-Restli-Protocol-Version': '2.0.0',
#                             'LinkedIn-Version': '202308'  # Add API version header
#                         }

#                         # Get user's LinkedIn URN with proper API version
#                         try:
#                             user_info_url = 'https://api.linkedin.com/v2/me'
#                             user_response = requests.get(
#                                 user_info_url, 
#                                 headers=headers
#                             )
                            
#                             if user_response.status_code == 401:
#                                 errors.append("LinkedIn access token expired or invalid")
#                                 continue
#                             elif user_response.status_code == 403:
#                                 errors.append("LinkedIn permission denied. Please check app permissions")
#                                 continue
#                             elif user_response.status_code != 200:
#                                 errors.append(f"Failed to get LinkedIn user info: {user_response.text}")
#                                 continue
                            
#                             user_urn = user_response.json().get('id')
#                             if not user_urn:
#                                 errors.append("LinkedIn user ID not found in response")
#                                 continue

#                             if media_file:
#                                 # Register upload
#                                 register_upload_url = 'https://api.linkedin.com/v2/assets?action=registerUpload'
#                                 register_data = {
#                                     "registerUploadRequest": {
#                                         "recipes": ["urn:li:digitalmediaRecipe:feedshare-image"],
#                                         "owner": f"urn:li:person:{user_urn}",
#                                         "serviceRelationships": [{
#                                             "relationshipType": "OWNER",
#                                             "identifier": "urn:li:userGeneratedContent"
#                                         }]
#                                     }
#                                 }
                                
#                                 upload_response = requests.post(
#                                     register_upload_url, 
#                                     headers=headers, 
#                                     json=register_data
#                                 )

#                                 if upload_response.status_code != 200:
#                                     errors.append("Failed to register LinkedIn media upload")
#                                     continue

#                                 # Get upload URL and asset URN
#                                 upload_url = upload_response.json()['value']['uploadMechanism']['com.linkedin.digitalmedia.uploading.MediaUploadHttpRequest']['uploadUrl']
#                                 asset_urn = upload_response.json()['value']['asset']

#                                 # Upload the image
#                                 with open(post.media.path, 'rb') as image:
#                                     files = {'file': image}
#                                     image_upload_response = requests.post(upload_url, files=files)
                                    
#                                     if image_upload_response.status_code != 201:
#                                         errors.append("Failed to upload image to LinkedIn")
#                                         continue

#                                 # Create post with image
#                                 post_url = 'https://api.linkedin.com/v2/ugcPosts'
#                                 post_data = {
#                                     "author": f"urn:li:person:{user_urn}",
#                                     "lifecycleState": "PUBLISHED",
#                                     "specificContent": {
#                                         "com.linkedin.ugc.ShareContent": {
#                                             "shareCommentary": {
#                                                 "text": content
#                                             },
#                                             "shareMediaCategory": "IMAGE",
#                                             "media": [{
#                                                 "status": "READY",
#                                                 "description": {
#                                                     "text": content
#                                                 },
#                                                 "media": asset_urn,
#                                             }]
#                                         }
#                                     },
#                                     "visibility": {
#                                         "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
#                                     }
#                                 }
#                             else:
#                                 # Text-only post
#                                 post_url = 'https://api.linkedin.com/v2/ugcPosts'
#                                 post_data = {
#                                     "author": f"urn:li:person:{user_urn}",
#                                     "lifecycleState": "PUBLISHED",
#                                     "specificContent": {
#                                         "com.linkedin.ugc.ShareContent": {
#                                             "shareCommentary": {
#                                                 "text": content
#                                             },
#                                             "shareMediaCategory": "NONE"
#                                         }
#                                     },
#                                     "visibility": {
#                                         "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
#                                     }
#                                 }

#                             response = requests.post(post_url, headers=headers, json=post_data)
#                             if response.status_code in [200, 201]:
#                                 is_published = True
#                             else:
#                                 errors.append(f"Failed to post to LinkedIn: {response.text}")

#                         except requests.exceptions.RequestException as e:
#                             errors.append(f"Network error while posting to LinkedIn: {str(e)}")
#                         except Exception as e:
#                             errors.append(f"Error posting to LinkedIn: {str(e)}")

#                 except Credential.DoesNotExist:
#                     errors.append(f"No credentials found for {platform.platform}")
#                 except Exception as e:
#                     errors.append(f"Error posting to {platform.platform}: {str(e)}")

#             # Update post status
#             post.is_published = is_published
#             post.save()

#             return Response({
#                 'message': 'Post created successfully' if is_published else 'Post created but failed to publish',
#                 'post_id': post.id,
#                 'is_published': is_published,
#                 'errors': errors
#             })

#         except Exception as e:
#             return Response({
#                 'error': f'Failed to create post: {str(e)}'
#             }, status=status.HTTP_400_BAD_REQUEST)

#     def post_to_facebook(self, post, user):
#         try:
#             # Get Facebook credentials
#             cred = Credential.objects.get(user=user, platform_name='facebook')
            
#             # Create media attachment if exists
#             attachment = {}
#             if post.media:
#                 if self._is_image(post.media.name):
#                     attachment = {
#                         'media_fbid': self._upload_photo_to_facebook(post.media, cred.access_token)
#                     }
#                 elif self._is_video(post.media.name):
#                     attachment = {
#                         'media_fbid': self._upload_video_to_facebook(post.media, cred.access_token)
#                     }

#             # Post to Facebook
#             graph = facebook.GraphAPI(access_token=cred.access_token)
#             graph.put_object(
#                 parent_object='me',
#                 connection_name='feed',
#                 message=post.content,
#                 **attachment
#             )
#         except Exception as e:
#             raise Exception(f"Failed to post to Facebook: {str(e)}")

#     def post_to_linkedin(self, post, user):
#         try:
#             # Get LinkedIn credentials
#             cred = Credential.objects.get(user=user, platform_name='linkedin')
            
#             # Create media share if exists
#             media_asset = None
#             if post.media:
#                 if self._is_image(post.media.name):
#                     media_asset = self._upload_image_to_linkedin(post.media, cred.access_token)
#                 elif self._is_video(post.media.name):
#                     media_asset = self._upload_video_to_linkedin(post.media, cred.access_token)

#             # Post to LinkedIn
#             headers = {
#                 'Authorization': f'Bearer {cred.access_token}',
#                 'Content-Type': 'application/json',
#             }
            
#             payload = {
#                 'author': f'urn:li:person:{user.social_id}',
#                 'lifecycleState': 'PUBLISHED',
#                 'specificContent': {
#                     'com.linkedin.ugc.ShareContent': {
#                         'shareCommentary': {
#                             'text': post.content
#                         },
#                         'shareMediaCategory': 'NONE'
#                     }
#                 },
#                 'visibility': {
#                     'com.linkedin.ugc.MemberNetworkVisibility': 'PUBLIC'
#                 }
#             }

#             if media_asset:
#                 payload['specificContent']['com.linkedin.ugc.ShareContent']['shareMediaCategory'] = 'IMAGE' if self._is_image(post.media.name) else 'VIDEO'
#                 payload['specificContent']['com.linkedin.ugc.ShareContent']['media'] = [media_asset]

#             response = requests.post(
#                 'https://api.linkedin.com/v2/ugcPosts',
#                 headers=headers,
#                 json=payload
#             )
            
#             if response.status_code != 201:
#                 raise Exception(f"LinkedIn API error: {response.text}")

#         except Exception as e:
#             raise Exception(f"Failed to post to LinkedIn: {str(e)}")

#     def _is_image(self, filename):
#         return filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp'))

#     def _is_video(self, filename):
#         return filename.lower().endswith(('.mp4', '.mov', '.avi', '.wmv'))

#     def _get_page_access_token(self, user_access_token):
#         """Get Facebook page access token."""
#         url = f"https://graph.facebook.com/v22.0/{settings.FACEBOOK_PAGE_ID}?fields=access_token&access_token={user_access_token}"
#         response = requests.get(url)
#         if response.status_code == 200:
#             return response.json().get('access_token')
#         return None

#     def _publish_post(self, post):
#         publishing_errors = []
#         for platform in post.platforms.all():
#             try:
#                 credentials = SocialMediaCredentials.objects.get(
#                     user=post.user,
#                     platform_name=platform.platform
#                 )

#                 if platform.platform == 'facebook':
#                     access_token = self.get_valid_facebook_token(credentials)
#                     if not access_token:
#                         publishing_errors.append('Failed to get valid Facebook access token')
#                         continue

#                     page_token = self._get_page_access_token(access_token)
#                     if not page_token:
#                         publishing_errors.append('Failed to get Facebook page access token')
#                         continue

#                     url = f"https://graph.facebook.com/v22.0/{settings.FACEBOOK_PAGE_ID}/feed"
#                     params = {
#                         "message": post.content,
#                         "access_token": page_token
#                     }
                    
#                     if post.media:
#                         media_url = f"{settings.SITE_URL}{post.media.url}"
#                         params["link"] = media_url

#                     response = requests.post(url, params=params)
#                     if response.status_code != 200:
#                         publishing_errors.append(f'Facebook posting failed: {response.text}')

#                 elif platform.platform == 'linkedin':
#                     access_token = self.get_valid_linkedin_token(credentials)
#                     if not access_token:
#                         publishing_errors.append('Failed to get valid LinkedIn access token')
#                         continue

#                     headers = {
#                         "Authorization": f"Bearer {access_token}",
#                         "Content-Type": "application/json",
#                         "X-Restli-Protocol-Version": "2.0.0"
#                     }
                    
#                     post_data = {
#                         "author": f"urn:li:person:{settings.LINKEDIN_USER_ID}",
#                         "lifecycleState": "PUBLISHED",
#                         "specificContent": {
#                             "com.linkedin.ugc.ShareContent": {
#                                 "shareCommentary": {
#                                     "text": post.content
#                                 },
#                                 "shareMediaCategory": "NONE"
#                             }
#                         },
#                         "visibility": {
#                             "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
#                         }
#                     }
                    
#                     if post.media:
#                         media_asset = self._upload_media_to_linkedin(post.media, access_token)
#                         if media_asset:
#                             post_data["specificContent"]["com.linkedin.ugc.ShareContent"]["shareMediaCategory"] = "IMAGE"
#                             post_data["specificContent"]["com.linkedin.ugc.ShareContent"]["media"] = [{
#                                 "status": "READY",
#                                 "media": media_asset,
#                                 "title": {
#                                     "text": "Image"
#                                 }
#                             }]

#                     response = requests.post(
#                         "https://api.linkedin.com/v2/ugcPosts",
#                         headers=headers,
#                         json=post_data
#                     )
                    
#                     if response.status_code not in [200, 201]:
#                         publishing_errors.append(f'LinkedIn posting failed: {response.text}')

#             except SocialMediaCredentials.DoesNotExist:
#                 publishing_errors.append(f'No credentials found for {platform.platform}')
#             except Exception as e:
#                 publishing_errors.append(f'Error posting to {platform.platform}: {str(e)}')

#         return publishing_errors

#     def _get_page_access_token(self, user_access_token):
#         try:
#             url = f"https://graph.facebook.com/v22.0/{settings.FACEBOOK_PAGE_ID}?fields=access_token&access_token={user_access_token}"
#             response = requests.get(url)
#             if response.status_code == 200:
#                 return response.json().get('access_token')
#             return None
#         except Exception:
#             return None

#     def _upload_media_to_linkedin(self, media_file, access_token):
#         try:
#             # Register media upload
#             register_headers = {
#                 "Authorization": f"Bearer {access_token}",
#                 "Content-Type": "application/json",
#                 "X-Restli-Protocol-Version": "2.0.0"
#             }
            
#             register_data = {
#                 "registerUploadRequest": {
#                     "recipes": ["urn:li:digitalmediaRecipe:feedshare-image"],
#                     "owner": f"urn:li:person:{settings.LINKEDIN_USER_ID}",
#                     "serviceRelationships": [{
#                         "relationshipType": "OWNER",
#                         "identifier": "urn:li:userGeneratedContent"
#                     }]
#                 }
#             }
            
#             response = requests.post(
#                 "https://api.linkedin.com/v2/assets?action=registerUpload",
#                 headers=register_headers,
#                 json=register_data
#             )
            
#             if response.status_code != 200:
#                 return None
                
#             upload_url = response.json()["value"]["uploadMechanism"]["com.linkedin.digitalmedia.uploading.MediaUploadHttpRequest"]["uploadUrl"]
#             asset = response.json()["value"]["asset"]
            
#             # Upload the image
#             with media_file.open('rb') as image:
#                 upload_response = requests.put(
#                     upload_url,
#                     data=image,
#                     headers={
#                         "Authorization": f"Bearer {access_token}"
#                     }
#                 )
                
#                 if upload_response.status_code == 201:
#                     return asset
                    
#             return None
#         except Exception:
#             return None

class CreatePostView(APIView):
    authentication_classes = [MultiPlatformTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        content = request.data.get('content', '')
        enable_likes = request.data.get('enable_likes', True)
        enable_comments = request.data.get('enable_comments', True)
        media_file = request.FILES.get('media')

        try:
            # Create post instance
            post = Post.objects.create(
                user=request.user,
                content=content,
                media=media_file,
                is_published=False,
                enable_likes=enable_likes,
                enable_comments=enable_comments
            )

            errors = []
            is_published = False

            # Get selected platforms
            selected_platforms = SelectedPlatform.objects.filter(
                user=request.user,
                is_selected=True
            )

            for platform in selected_platforms:
                try:
                    credentials = Credential.objects.get(
                        user=request.user,
                        platform_name=platform.platform
                    )

                    if platform.platform == 'linkedin':
                        # LinkedIn posting logic with profile info
                        headers = {
                            'Authorization': f'Bearer {credentials.access_token}',
                            'Content-Type': 'application/json',
                            'X-Restli-Protocol-Version': '2.0.0',
                            'LinkedIn-Version': '202308'
                        }

                        # Get user's LinkedIn URN using email
                        user_info_url = 'https://api.linkedin.com/v2/userinfo'
                        user_response = requests.get(user_info_url, headers=headers)
                        
                        if user_response.status_code != 200:
                            errors.append(f"Failed to get LinkedIn user info: {user_response.text}")
                            continue
                        
                        user_data = user_response.json()
                        user_urn = user_data.get('sub')  # Using sub as URN from OAuth userinfo

                        if media_file:
                            # Register upload
                            register_upload_url = 'https://api.linkedin.com/v2/assets?action=registerUpload'
                            register_data = {
                                "registerUploadRequest": {
                                    "recipes": ["urn:li:digitalmediaRecipe:feedshare-image"],
                                    "owner": f"urn:li:person:{user_urn}",
                                    "serviceRelationships": [{
                                        "relationshipType": "OWNER",
                                        "identifier": "urn:li:userGeneratedContent"
                                    }]
                                }
                            }
                            
                            upload_response = requests.post(
                                register_upload_url, 
                                headers=headers, 
                                json=register_data
                            )

                            if upload_response.status_code != 200:
                                errors.append(f"Failed to register LinkedIn media upload: {upload_response.text}")
                                continue

                            # Get upload URL and asset URN
                            upload_data = upload_response.json()
                            upload_url = upload_data['value']['uploadMechanism']['com.linkedin.digitalmedia.uploading.MediaUploadHttpRequest']['uploadUrl']
                            asset_urn = upload_data['value']['asset']

                            # Upload the image
                            with open(post.media.path, 'rb') as image:
                                image_headers = {
                                    'Authorization': f'Bearer {credentials.access_token}'
                                }
                                files = {'file': image}
                                image_upload_response = requests.post(upload_url, headers=image_headers, files=files)
                                
                                if image_upload_response.status_code != 201:
                                    errors.append(f"Failed to upload image to LinkedIn: {image_upload_response.text}")
                                    continue

                            # Create post with image
                            post_url = 'https://api.linkedin.com/v2/ugcPosts'
                            post_data = {
                                "author": f"urn:li:person:{user_urn}",
                                "lifecycleState": "PUBLISHED",
                                "specificContent": {
                                    "com.linkedin.ugc.ShareContent": {
                                        "shareCommentary": {
                                            "text": content
                                        },
                                        "shareMediaCategory": "IMAGE",
                                        "media": [{
                                            "status": "READY",
                                            "description": {
                                                "text": content
                                            },
                                            "media": asset_urn,
                                            "title": {
                                                "text": f"Post by {user_data.get('name', 'User')}"
                                            }
                                        }]
                                    }
                                },
                                "visibility": {
                                    "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
                                }
                            }

                            response = requests.post(post_url, headers=headers, json=post_data)
                            if response.status_code in [200, 201]:
                                is_published = True
                            else:
                                errors.append(f"Failed to post to LinkedIn: {response.text}")

                except Credential.DoesNotExist:
                    errors.append(f"No credentials found for {platform.platform}")
                except Exception as e:
                    errors.append(f"Error posting to {platform.platform}: {str(e)}")

            # Update post status
            post.is_published = is_published
            post.save()

            return Response({
                'message': 'Post created successfully' if is_published else 'Post created but failed to publish',
                'post_id': post.id,
                'is_published': is_published,
                'errors': errors
            })

        except Exception as e:
            return Response({
                'error': f'Failed to create post: {str(e)}'
            }, status=status.HTTP_400_BAD_REQUEST)

    def post_to_facebook(self, post, user):
        try:
            # Get Facebook credentials
            cred = Credential.objects.get(user=user, platform_name='facebook')
            
            # Create media attachment if exists
            attachment = {}
            if post.media:
                if self._is_image(post.media.name):
                    attachment = {
                        'media_fbid': self._upload_photo_to_facebook(post.media, cred.access_token)
                    }
                elif self._is_video(post.media.name):
                    attachment = {
                        'media_fbid': self._upload_video_to_facebook(post.media, cred.access_token)
                    }

            # Post to Facebook
            graph = facebook.GraphAPI(access_token=cred.access_token)
            graph.put_object(
                parent_object='me',
                connection_name='feed',
                message=post.content,
                **attachment
            )
        except Exception as e:
            raise Exception(f"Failed to post to Facebook: {str(e)}")

    def post_to_linkedin(self, post, user):
        try:
            # Get LinkedIn credentials
            cred = Credential.objects.get(user=user, platform_name='linkedin')
            
            # Create media share if exists
            media_asset = None
            if post.media:
                if self._is_image(post.media.name):
                    media_asset = self._upload_image_to_linkedin(post.media, cred.access_token)
                elif self._is_video(post.media.name):
                    media_asset = self._upload_video_to_linkedin(post.media, cred.access_token)

            # Post to LinkedIn
            headers = {
                'Authorization': f'Bearer {cred.access_token}',
                'Content-Type': 'application/json',
            }
            
            payload = {
                'author': f'urn:li:person:{user.social_id}',
                'lifecycleState': 'PUBLISHED',
                'specificContent': {
                    'com.linkedin.ugc.ShareContent': {
                        'shareCommentary': {
                            'text': post.content
                        },
                        'shareMediaCategory': 'NONE'
                    }
                },
                'visibility': {
                    'com.linkedin.ugc.MemberNetworkVisibility': 'PUBLIC'
                }
            }

            if media_asset:
                payload['specificContent']['com.linkedin.ugc.ShareContent']['shareMediaCategory'] = 'IMAGE' if self._is_image(post.media.name) else 'VIDEO'
                payload['specificContent']['com.linkedin.ugc.ShareContent']['media'] = [media_asset]

            response = requests.post(
                'https://api.linkedin.com/v2/ugcPosts',
                headers=headers,
                json=payload
            )
            
            if response.status_code != 201:
                raise Exception(f"LinkedIn API error: {response.text}")

        except Exception as e:
            raise Exception(f"Failed to post to LinkedIn: {str(e)}")

    def _is_image(self, filename):
        return filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp'))

    def _is_video(self, filename):
        return filename.lower().endswith(('.mp4', '.mov', '.avi', '.wmv'))

    def _get_page_access_token(self, user_access_token):
        """Get Facebook page access token."""
        url = f"https://graph.facebook.com/v22.0/{settings.FACEBOOK_PAGE_ID}?fields=access_token&access_token={user_access_token}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json().get('access_token')
        return None

    def _publish_post(self, post):
        publishing_errors = []
        for platform in post.platforms.all():
            try:
                credentials = SocialMediaCredentials.objects.get(
                    user=post.user,
                    platform_name=platform.platform
                )

                if platform.platform == 'facebook':
                    access_token = self.get_valid_facebook_token(credentials)
                    if not access_token:
                        publishing_errors.append('Failed to get valid Facebook access token')
                        continue

                    page_token = self._get_page_access_token(access_token)
                    if not page_token:
                        publishing_errors.append('Failed to get Facebook page access token')
                        continue

                    url = f"https://graph.facebook.com/v22.0/{settings.FACEBOOK_PAGE_ID}/feed"
                    params = {
                        "message": post.content,
                        "access_token": page_token
                    }
                    
                    if post.media:
                        media_url = f"{settings.SITE_URL}{post.media.url}"
                        params["link"] = media_url

                    response = requests.post(url, params=params)
                    if response.status_code != 200:
                        publishing_errors.append(f'Facebook posting failed: {response.text}')

                elif platform.platform == 'linkedin':
                    access_token = self.get_valid_linkedin_token(credentials)
                    if not access_token:
                        publishing_errors.append('Failed to get valid LinkedIn access token')
                        continue

                    headers = {
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json",
                        "X-Restli-Protocol-Version": "2.0.0"
                    }
                    
                    post_data = {
                        "author": f"urn:li:person:{settings.LINKEDIN_USER_ID}",
                        "lifecycleState": "PUBLISHED",
                        "specificContent": {
                            "com.linkedin.ugc.ShareContent": {
                                "shareCommentary": {
                                    "text": post.content
                                },
                                "shareMediaCategory": "NONE"
                            }
                        },
                        "visibility": {
                            "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
                        }
                    }
                    
                    if post.media:
                        media_asset = self._upload_media_to_linkedin(post.media, access_token)
                        if media_asset:
                            post_data["specificContent"]["com.linkedin.ugc.ShareContent"]["shareMediaCategory"] = "IMAGE"
                            post_data["specificContent"]["com.linkedin.ugc.ShareContent"]["media"] = [{
                                "status": "READY",
                                "media": media_asset,
                                "title": {
                                    "text": "Image"
                                }
                            }]

                    response = requests.post(
                        "https://api.linkedin.com/v2/ugcPosts",
                        headers=headers,
                        json=post_data
                    )
                    
                    if response.status_code not in [200, 201]:
                        publishing_errors.append(f'LinkedIn posting failed: {response.text}')

            except SocialMediaCredentials.DoesNotExist:
                publishing_errors.append(f'No credentials found for {platform.platform}')
            except Exception as e:
                publishing_errors.append(f'Error posting to {platform.platform}: {str(e)}')

        return publishing_errors

    def _get_page_access_token(self, user_access_token):
        try:
            url = f"https://graph.facebook.com/v22.0/{settings.FACEBOOK_PAGE_ID}?fields=access_token&access_token={user_access_token}"
            response = requests.get(url)
            if response.status_code == 200:
                return response.json().get('access_token')
            return None
        except Exception:
            return None

    def _upload_media_to_linkedin(self, media_file, access_token):
        try:
            # Register media upload
            register_headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "X-Restli-Protocol-Version": "2.0.0"
            }
            
            register_data = {
                "registerUploadRequest": {
                    "recipes": ["urn:li:digitalmediaRecipe:feedshare-image"],
                    "owner": f"urn:li:person:{settings.LINKEDIN_USER_ID}",
                    "serviceRelationships": [{
                        "relationshipType": "OWNER",
                        "identifier": "urn:li:userGeneratedContent"
                    }]
                }
            }
            
            response = requests.post(
                "https://api.linkedin.com/v2/assets?action=registerUpload",
                headers=register_headers,
                json=register_data
            )
            
            if response.status_code != 200:
                return None
                
            upload_url = response.json()["value"]["uploadMechanism"]["com.linkedin.digitalmedia.uploading.MediaUploadHttpRequest"]["uploadUrl"]
            asset = response.json()["value"]["asset"]
            
            # Upload the image
            with media_file.open('rb') as image:
                upload_response = requests.put(
                    upload_url,
                    data=image,
                    headers={
                        "Authorization": f"Bearer {access_token}"
                    }
                )
                
                if upload_response.status_code == 201:
                    return asset
                    
            return None
        except Exception:
            return None


class MultiPlatformTokenAuthentication(TokenAuthentication):
    def authenticate(self, request):
        # Get primary token
        primary_auth = super().authenticate(request)
        if not primary_auth:
            return None

        user, _ = primary_auth

        # Get secondary token if exists
        secondary_token = request.headers.get('X-Secondary-Token')
        if secondary_token:
            try:
                Token.objects.get(key=secondary_token)
                # Store secondary token in request for later use
                request.secondary_token = secondary_token
            except Token.DoesNotExist:
                pass

        return (user, None)

from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated

class CheckCredentialsView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        social_credentials = {
            'provider': user.social_provider,
            'is_authenticated': True,
            'platforms': []
        }

        # Get user's selected platforms
        platforms = SelectedPlatform.objects.filter(user=user)
        
        if user.social_provider:
            platform_info = {
                'facebook': {'name': 'Facebook', 'key': 'facebook'},
                'linkedin': {'name': 'LinkedIn', 'key': 'linkedin'},
                'instagram': {'name': 'Instagram', 'key': 'instagram'}
            }
            
            if user.social_provider in platform_info:
                platform = platform_info[user.social_provider].copy()
                platform['is_selected'] = platforms.filter(
                    platform=platform['key'], 
                    is_selected=True
                ).exists()
                social_credentials['platforms'].append(platform)

        return Response(social_credentials, status=status.HTTP_200_OK)


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

class FacebookAuthView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Facebook OAuth configuration
        client_id = settings.FACEBOOK_APP_ID
        redirect_uri = settings.FACEBOOK_REDIRECT_URI
        scope = 'pages_manage_posts,pages_read_engagement'
        
        # Facebook OAuth URL
        auth_url = f"https://www.facebook.com/v18.0/dialog/oauth?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}"
        
        return Response({
            'authorization_url': auth_url
        })

from urllib.parse import urlencode
from django.shortcuts import redirect
from urllib.parse import urlencode

def facebook_authorize(request):
    # Facebook OAuth configuration from settings
    client_id = settings.FACEBOOK_APP_ID
    redirect_uri = settings.FACEBOOK_REDIRECT_URI
    scope = 'pages_manage_posts,pages_read_engagement'
    
    # Construct Facebook OAuth URL
    auth_url = f"https://www.facebook.com/v18.0/dialog/oauth?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}"
    
    # Redirect to Facebook authorization page
    return redirect(auth_url)

@api_view(['GET'])
def linkedin_authorize(request):
    """Generate LinkedIn OAuth2 authorization URL and redirect user."""
    params = {
        'response_type': 'code',
        'client_id': settings.LINKEDIN_CLIENT_ID,
        'redirect_uri': f'{settings.SITE_URL}/api/auth/linkedin/callback/',
        'scope': 'openid profile w_member_social email',
        'state': 'random_state_string'  # You should generate this dynamically for security
    }
    
    auth_url = f'https://www.linkedin.com/oauth/v2/authorization?{urlencode(params)}'
    return redirect(auth_url)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_post(request):
    try:
        data = request.data
        responses = {}
        
        if data.get('platforms') & 2:  # Facebook
            responses['facebook'] = post_to_facebook(request.user.id, data['content'])
            
        if data.get('platforms') & 4:  # LinkedIn
            responses['linkedin'] = post_to_linkedin(request.user.id, data['content'])

        return Response(responses)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


class OAuthCallbackView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        code = request.GET.get('code')
        if not code:
            return Response({'error': 'No authorization code provided'}, 
                          status=status.HTTP_400_BAD_REQUEST)

        # Determine which platform callback this is
        path = request.path
        platform_name = 'facebook' if 'facebook' in path else 'linkedin'
        
        if platform_name == 'facebook':
            token_data = exchange_code_for_token(code)
        else:
            token_data = exchange_linkedin_code_for_token(code)

        if 'access_token' in token_data:
            try:
                credentials = Credentials.objects.get(
                    user=request.user,
                    platform_name=platform_name
                )
                credentials.access_token = token_data['access_token']
                credentials.token_expires_at = token_data.get('expires_at')
                credentials.token_type = token_data.get('token_type')
                credentials.save()
            except Credentials.DoesNotExist:
                Credentials.objects.create(
                    user=request.user,
                    platform_name=platform_name,
                    username=request.user.email,
                    access_token=token_data['access_token'],
                    token_expires_at=token_data.get('expires_at'),
                    token_type=token_data.get('token_type')
                )

            return Response({
                'status': 'success',
                'message': f'{platform_name.capitalize()} authentication successful'
            })
        else:
            return Response({
                'status': 'error',
                'message': token_data.get('message', 'Failed to obtain access token')
            }, status=status.HTTP_400_BAD_REQUEST)


class SocialPostView(APIView):
    authentication_classes = [MultiPlatformTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        content = request.data.get('content')
        media = request.data.get('media')
        if not content:
            return Response({'error': 'Content is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Get user's selected platforms
        selected_platforms = SelectedPlatform.objects.filter(
            user=request.user,
            is_selected=True
        )

        if not selected_platforms.exists():
            return Response({'error': 'No platforms selected'}, status=status.HTTP_400_BAD_REQUEST)

        response_data = {
            'message': 'Post created but some platforms failed to publish',
            'post_id': None,
            'is_published': False,
            'errors': []
        }

        for platform in selected_platforms:
            try:
                # Look up credentials using platform name
                credentials = Credential.objects.get(
                    user=request.user,
                    platform_name=platform.platform
                )

                if platform.platform == 'facebook':
                    # Facebook Graph API endpoint
                    url = f"https://graph.facebook.com/v18.0/me/feed"
                    headers = {
                        "Authorization": f"Bearer {credentials.access_token}",
                        "Content-Type": "application/json"
                    }
                    
                    post_data = {
                        "message": content
                    }
                    
                    if media:
                        # If media is present, first upload it to Facebook
                        media_url = f"https://graph.facebook.com/v18.0/me/photos"
                        media_data = {
                            "url": media,
                            "published": False
                        }
                        media_response = requests.post(media_url, headers=headers, json=media_data)
                        if media_response.status_code == 200:
                            media_id = media_response.json().get('id')
                            post_data["attached_media"] = [{"media_fbid": media_id}]

                    response = requests.post(url, headers=headers, json=post_data)
                    
                    if response.status_code == 200:
                        response_data['is_published'] = True
                        response_data['post_id'] = response.json().get('id')
                        response_data['message'] = 'Post created successfully'
                    else:
                        response_data['errors'].append(f"Failed to post to Facebook: {response.text}")

                elif platform.platform == 'linkedin':
                    # LinkedIn Share API endpoint
                    url = "https://api.linkedin.com/v2/ugcPosts"
                    headers = {
                        "Authorization": f"Bearer {credentials.access_token}",  # Using access_token instead of password
                        "Content-Type": "application/json",
                        "X-Restli-Protocol-Version": "2.0.0"
                    }
                    
                    post_data = {
                        "author": f"urn:li:person:{credentials.platform_user_id}",  # Using platform_user_id from credentials
                        "lifecycleState": "PUBLISHED",
                        "specificContent": {
                            "com.linkedin.ugc.ShareContent": {
                                "shareCommentary": {
                                    "text": content
                                },
                                "shareMediaCategory": "NONE"
                            }
                        },
                        "visibility": {
                            "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
                        }
                    }
                    
                    response = requests.post(url, json=post_data, headers=headers)
                    
                    if response.status_code == 201:
                        response_data['is_published'] = True
                        response_data['post_id'] = response.json().get('id')
                    else:
                        response_data['errors'].append(f"Failed to post to {platform.platform}: {response.text}")

            except Credential.DoesNotExist:
                response_data['errors'].append(f"No credentials found for {platform.platform}")
            except Exception as e:
                response_data['errors'].append(f"Error posting to {platform.platform}: {str(e)}")

        if response_data['is_published'] and not response_data['errors']:
            response_data['message'] = 'Post created successfully'

        return Response(response_data, status=status.HTTP_200_OK)
