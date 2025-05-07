from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import viewsets, status, filters
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from django.contrib.auth.hashers import check_password
import jwt
from datetime import datetime, timedelta
from django.conf import settings
from django.utils.timezone import now
from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import requests
import uuid  # Add this import


from .models import User, Person
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
                    # For Instagram usernames
                    user = User.objects.get(name=username)
                
                # Update user if needed
                if not user.social_provider:
                    user.social_provider = provider
                    user.save()
            except User.DoesNotExist:
                # Create new user
                if '@' in username:
                    # Email login
                    user = User.objects.create(
                        email=username,
                        name=username.split('@')[0],
                        phone_number=f'temp_{str(uuid.uuid4())[:8]}',
                        gender=''
                    )
                elif username.isdigit():
                    # Phone number login
                    user = User.objects.create(
                        email=f'{username}@temp.com',
                        name=f'user_{username}',
                        phone_number=username,
                        gender=''
                    )
                else:
                    # Instagram username login
                    user = User.objects.create(
                        email=f'{username}@instagram.temp',
                        name=username,  # Use Instagram username as name
                        phone_number=f'temp_{str(uuid.uuid4())[:8]}',
                        gender=''
                    )
                user.set_password(password)
                user.social_provider = provider
                user.save()

            # Generate token
            token = jwt.encode(
                {
                    'id': user.id,
                    'identifier': username,
                    'provider': provider,
                    'exp': datetime.utcnow() + timedelta(days=7)
                },
                settings.SECRET_KEY,
                algorithm='HS256'
            )

            return Response({
                'message': f'{provider.capitalize()} login successful',
                'userdata': {
                    'name': user.name,
                    'email': user.email,
                    'phone_number': user.phone_number,
                    'provider': provider
                },
                'token': token
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

    def authenticate_linkedin(self, username, password):
        api_url = 'https://www.linkedin.com/oauth/v2/accessToken'
        params = {
            'grant_type': 'client_credentials',
            'client_id': settings.LINKEDIN_CLIENT_ID,
            'client_secret': settings.LINKEDIN_CLIENT_SECRET
        }
        response = requests.post(api_url, params=params)
        if response.status_code == 200:
            data = response.json()
            return {
                'success': True,
                'access_token': data.get('access_token')
            }
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
                'scope': 'r_liteprofile r_emailaddress'
            }
        }
        
        if provider in configs:
            config = configs[provider]
            if provider == 'instagram':
                return f'https://api.instagram.com/oauth/authorize?client_id={config["client_id"]}&redirect_uri={config["redirect_uri"]}&scope={config["scope"]}&response_type=code'
            elif provider == 'linkedin':
                return f'https://www.linkedin.com/oauth/v2/authorization?client_id={config["client_id"]}&redirect_uri={config["redirect_uri"]}&scope={config["scope"]}&response_type=code'
            elif provider == 'facebook':
                return f'https://www.facebook.com/v12.0/dialog/oauth?client_id={config["client_id"]}&redirect_uri={config["redirect_uri"]}&scope={config["scope"]}'
