FACEBOOK_PAGE_ACCESS_TOKEN=new_facebook_access_token
FACEBOOK_PAGE_ID=your_facebook_page_id
LINKEDIN_ACCESS_TOKEN=new_linkedin_access_token
LINKEDIN_ORGANIZATION_ID=your_linkedin_organization_id

import os
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Facebook API credentials
FACEBOOK_PAGE_ACCESS_TOKEN = os.getenv("FACEBOOK_PAGE_ACCESS_TOKEN")
FACEBOOK_PAGE_ID = os.getenv("FACEBOOK_PAGE_ID")

# LinkedIn API credentials
LINKEDIN_ACCESS_TOKEN = os.getenv("LINKEDIN_ACCESS_TOKEN")
LINKEDIN_ORGANIZATION_ID = os.getenv("LINKEDIN_ORGANIZATION_ID")

def post_to_facebook(message):
    url = f"https://graph.facebook.com/{FACEBOOK_PAGE_ID}/feed"
    payload = {
        "message": message,
        "access_token": FACEBOOK_PAGE_ACCESS_TOKEN,
    }
    response = requests.post(url, data=payload)
    if response.status_code == 200:
        print("Posted to Facebook successfully!")
    else:
        print(f"Failed to post to Facebook: {response.text}")

def post_to_linkedin(message):
    url = f"https://api.linkedin.com/v2/ugcPosts"
    headers = {
        "Authorization": f"Bearer {LINKEDIN_ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "author": f"urn:li:organization:{LINKEDIN_ORGANIZATION_ID}",
        "lifecycleState": "PUBLISHED",
        "specificContent": {
            "com.linkedin.ugc.ShareContent": {
                "shareCommentary": {"text": message},
                "shareMediaCategory": "NONE",
            }
        },
        "visibility": {"com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"},
    }
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 201:
        print("Posted to LinkedIn successfully!")
    else:
        print(f"Failed to post to LinkedIn: {response.text}")

if __name__ == "__main__":
    message = "Your message to post on social media."
    post_to_facebook(message)
    post_to_linkedin(message)