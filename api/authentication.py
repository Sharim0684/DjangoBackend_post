from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token

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