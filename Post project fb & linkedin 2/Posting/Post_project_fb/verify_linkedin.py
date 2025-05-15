import requests
import os
from dotenv import load_dotenv

load_dotenv()

def verify_linkedin_token():
    token = os.getenv("LINKEDIN_ACCESS_TOKEN")
    user_id = os.getenv("LINKEDIN_USER_ID")
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    
    url = "https://api.linkedin.com/v2/ugcPosts"
    
    post_data = {
        "author": f"urn:li:person:{user_id}",
        "lifecycleState": "PUBLISHED",
        "specificContent": {
            "com.linkedin.ugc.ShareContent": {
                "shareCommentary": {
                    "text": "hello everyone"
                },
                "shareMediaCategory": "NONE"
            }
        },
        "visibility": {
            "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
        }
    }
    
    response = requests.post(url, headers=headers, json=post_data)
    print("Status:", response.status_code)
    print("Response:", response.text)

if __name__ == "__main__":
    verify_linkedin_token()