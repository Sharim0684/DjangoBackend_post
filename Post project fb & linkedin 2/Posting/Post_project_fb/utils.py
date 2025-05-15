from dotenv import load_dotenv
import requests
import os
import json
from datetime import datetime, timedelta

load_dotenv()

FACEBOOK_APP_ID = os.getenv("FACEBOOK_APP_ID")
FACEBOOK_APP_SECRET = os.getenv("FACEBOOK_APP_SECRET")
FACEBOOK_REDIRECT_URI = os.getenv("FACEBOOK_REDIRECT_URI")
PAGE_ID = os.getenv("FACEBOOK_PAGE_ID")
ACCESS_TOKEN_FILE = "access_token.json"

# Add LinkedIn variables
LINKEDIN_CLIENT_ID = os.getenv("LINKEDIN_CLIENT_ID")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET")
LINKEDIN_REDIRECT_URI = "http://localhost:8000/linkedin/callback"
LINKEDIN_USER_ID = os.getenv("LINKEDIN_USER_ID")
LINKEDIN_TOKEN_FILE = "linkedin_token.json"


def load_access_token():
    """Load access token from a file."""
    try:
        with open(ACCESS_TOKEN_FILE, "r") as file:
            data = json.load(file)
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def save_access_token(token_data):
    """Save access token and expiry to a file."""
    with open(ACCESS_TOKEN_FILE, "w") as file:
        json.dump(token_data, file)


def exchange_code_for_token(code: str):
    """Exchange authorization code for an access token."""
    url = "https://graph.facebook.com/v22.0/oauth/access_token"
    params = {
        "client_id": FACEBOOK_APP_ID,
        "redirect_uri": FACEBOOK_REDIRECT_URI,
        "client_secret": FACEBOOK_APP_SECRET,
        "code": code,
    }
    response = requests.get(url, params=params)

    if response.status_code == 200:
        token_data = response.json()
        if "access_token" in token_data:
            token_data["expires_at"] = (datetime.utcnow() + timedelta(seconds=token_data.get("expires_in", 3600))).timestamp()
            save_access_token(token_data)
            return token_data
    return {"status": "error", "message": response.json()}


def exchange_for_long_lived_token(short_lived_token):
    """Exchange a short-lived token for a long-lived one."""
    url = "https://graph.facebook.com/v22.0/oauth/access_token"
    params = {
        "grant_type": "fb_exchange_token",
        "client_id": FACEBOOK_APP_ID,
        "client_secret": FACEBOOK_APP_SECRET,
        "fb_exchange_token": short_lived_token,
    }
    response = requests.get(url, params=params)

    if response.status_code == 200:
        token_data = response.json()
        if "access_token" in token_data:
            token_data["expires_at"] = (datetime.utcnow() + timedelta(days=60)).timestamp()
            save_access_token(token_data)
            return token_data
    return {"status": "error", "message": response.json()}


def get_valid_access_token():
    """Retrieve a valid access token, refreshing if necessary."""
    token_data = load_access_token()

    if not token_data or "access_token" not in token_data:
        return None

    expires_at = token_data.get("expires_at", 0)
    if datetime.utcnow().timestamp() > expires_at - 600:  # Refresh if less than 10 minutes remaining
        new_token_data = exchange_for_long_lived_token(token_data["access_token"])
        if "access_token" in new_token_data:
            return new_token_data["access_token"]
        return None  # Refresh failed, return None
    
    return token_data["access_token"]


def get_page_access_token(token):
    """Retrieve the Page Access Token every time before posting."""
    url = f"https://graph.facebook.com/v18.0/me/accounts?access_token={token}"
    response = requests.get(url)
    data = response.json()
    print(data)

    if "data" in data:
        for page in data["data"]:
            if page["id"] == PAGE_ID:
                return page["access_token"]
    return None


def post_to_facebook(message: str):
    """Post a message to Facebook."""
    access_token = get_valid_access_token()
    if not access_token:
        return {"status": "error", "message": "Missing or expired access token"}

    page_token = get_page_access_token(access_token)
    
    if not page_token:
        return {"status": "error", "message": "Failed to retrieve page access token"}

    url = f"https://graph.facebook.com/v22.0/{PAGE_ID}/feed"
    params = {"message": message, "access_token": page_token}

    response = requests.post(url, params=params)
    return response.json()


# Uncomment when needed and replace INSTAGRAM_BUSINESS_ID with the actual ID
# def post_to_instagram(caption: str, image_url: str):
#     """Post a photo with a caption to Instagram."""
#     access_token = get_valid_access_token()
#     if not access_token:
#         return {"status": "error", "message": "Missing or expired access token"}

#     # Step 1: Upload media container
#     url = f"https://graph.facebook.com/v22.0/{INSTAGRAM_BUSINESS_ID}/media"
#     params = {
#         "image_url": image_url,
#         "caption": caption,
#         "access_token": access_token,
#     }
#     response = requests.post(url, params=params)
#     container_data = response.json()

#     if "id" not in container_data:
#         return {"status": "error", "message": container_data}

#     # Step 2: Publish media container
#     publish_url = f"https://graph.facebook.com/v22.0/{INSTAGRAM_BUSINESS_ID}/media_publish"
#     publish_params = {
#         "creation_id": container_data["id"],
#         "access_token": access_token,
#     }
#     publish_response = requests.post(publish_url, params=publish_params)
#     return publish_response.json()u


def load_linkedin_token():
    """Load LinkedIn access token from a file."""
    try:
        with open(LINKEDIN_TOKEN_FILE, "r") as file:
            data = json.load(file)
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def save_linkedin_token(token_data):
    """Save LinkedIn access token and expiry to a file."""
    with open(LINKEDIN_TOKEN_FILE, "w") as file:
        json.dump(token_data, file)


def exchange_linkedin_code_for_token(code: str):
    """Exchange LinkedIn authorization code for an access token."""
    url = "https://www.linkedin.com/oauth/v2/accessToken"
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": LINKEDIN_CLIENT_ID,
        "client_secret": LINKEDIN_CLIENT_SECRET,
        "redirect_uri": LINKEDIN_REDIRECT_URI
    }
    
    response = requests.post(url, data=data)
    
    if response.status_code == 200:
        token_data = response.json()
        if "access_token" in token_data:
            token_data["expires_at"] = (datetime.utcnow() + 
                timedelta(seconds=token_data.get("expires_in", 3600))).timestamp()
            save_linkedin_token(token_data)
            return token_data
    return {"status": "error", "message": response.json()}


# Add after the Facebook token functions

def exchange_for_long_lived_linkedin_token(short_lived_token):
    """Exchange a short-lived LinkedIn token for a long-lived one."""
    url = "https://www.linkedin.com/oauth/v2/accessToken"
    data = {
        "grant_type": "refresh_token",
        "client_id": LINKEDIN_CLIENT_ID,
        "client_secret": LINKEDIN_CLIENT_SECRET,
        "refresh_token": short_lived_token
    }
    
    response = requests.post(url, data=data)
    
    if response.status_code == 200:
        token_data = response.json()
        if "access_token" in token_data:
            token_data["expires_at"] = (datetime.utcnow() + timedelta(days=60)).timestamp()
            save_linkedin_token(token_data)
            return token_data
    return {"status": "error", "message": response.json()}

# In the get_valid_linkedin_token function
def get_valid_linkedin_token():
    """Retrieve a valid LinkedIn access token."""
    # First try to get token from environment
    env_token = os.getenv("LINKEDIN_ACCESS_TOKEN")
    if env_token:
        return env_token
        
    # If no env token, try from file
    token_data = load_linkedin_token()
    if not token_data or "access_token" not in token_data:
        return None

    expires_at = token_data.get("expires_at", 0)
    if datetime.utcnow().timestamp() > expires_at - 600:
        new_token_data = exchange_for_long_lived_linkedin_token(token_data["access_token"])
        if "access_token" in new_token_data:
            return new_token_data["access_token"]
        return None
    
    return token_data["access_token"]


def post_to_linkedin(message: str):
    """Post a message to LinkedIn."""
    access_token = get_valid_linkedin_token()
    if not access_token:
        return {"status": "error", "message": "Missing or expired access token"}

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    url = "https://api.linkedin.com/v2/ugcPosts"
    
    post_data = {
        "author": f"urn:li:person:{LINKEDIN_USER_ID}",
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