from datetime import datetime, timedelta
import requests
from django.conf import settings
from .models import SocialMediaCredentials

def get_facebook_page_token(user_id):
    """Get Facebook page access token for a user."""
    try:
        credentials = SocialMediaCredentials.objects.get(user_id=user_id, platform='facebook')
        url = f"https://graph.facebook.com/v18.0/me/accounts?access_token={credentials.access_token}"
        response = requests.get(url)
        data = response.json()

        if "data" in data:
            for page in data["data"]:
                if page["id"] == settings.FACEBOOK_PAGE_ID:
                    return page["access_token"]
        return None
    except SocialMediaCredentials.DoesNotExist:
        return None

def post_to_facebook(user_id, message):
    """Post a message to Facebook page."""
    try:
        page_token = get_facebook_page_token(user_id)
        if not page_token:
            return {"status": "error", "message": "Failed to retrieve page access token"}

        url = f"https://graph.facebook.com/v18.0/{settings.FACEBOOK_PAGE_ID}/feed"
        params = {"message": message, "access_token": page_token}
        response = requests.post(url, params=params)
        return response.json()
    except Exception as e:
        return {"status": "error", "message": str(e)}

def get_linkedin_token(user_id):
    """Get LinkedIn access token for a user."""
    try:
        credentials = SocialMediaCredentials.objects.get(user_id=user_id, platform='linkedin')
        return credentials.access_token
    except SocialMediaCredentials.DoesNotExist:
        return None

def post_to_linkedin(user_id, message):
    """Post a message to LinkedIn."""
    try:
        access_token = get_linkedin_token(user_id)
        if not access_token:
            return {"status": "error", "message": "Missing or expired LinkedIn token"}

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
        
        url = "https://api.linkedin.com/v2/ugcPosts"
        post_data = {
            "author": f"urn:li:person:{settings.LINKEDIN_USER_ID}",
            "lifecycleState": "PUBLISHED",
            "specificContent": {
                "com.linkedin.ugc.ShareContent": {
                    "shareCommentary": {
                        "text": message
                    },
                    "shareMediaCategory": "NONE"
                }
            },
            "visibility": {
                "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
            }
        }
        
        response = requests.post(url, headers=headers, json=post_data)
        return response.json()
    except Exception as e:
        return {"status": "error", "message": str(e)}