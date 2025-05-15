import requests
import json

# Base URL
BASE_URL = "http://localhost:8000/api/"

def login(email, password):
    """Login and return the token using TokenAuthentication"""
    url = f"{BASE_URL}login/"
    data = {
        "email": email,
        "password": password
    }
    try:
        response = requests.post(url, json=data)
        if response.status_code == 200:
            # For TokenAuthentication, the token is in the 'token' field
            return response.json().get('token')
        print(f"Login failed: {response.status_code} - {response.text}")
        return None
    except Exception as e:
        print(f"Error during login: {str(e)}")
        return None

def create_post(token, content, platforms):
    """Create a post on selected platforms"""
    url = f"{BASE_URL}social/post/"  # Make sure this matches your Django URL
    headers = {
        "Authorization": f"Token {token}",  # Changed from Bearer to Token
        "Content-Type": "application/json"
    }
    data = {
        "content": content,
        "platforms": platforms,
        "enable_likes": True,
        "enable_comments": True
    }
    try:
        print(f"Sending request to: {url}")
        print(f"Headers: {headers}")
        print(f"Data: {data}")
        
        response = requests.post(url, headers=headers, json=data)
        return response
    except Exception as e:
        print(f"Error creating post: {str(e)}")
        return None

def main():
    # User credentials
    email = "shaikhsharim7@gmail.com"
    password = "Password@#123"
    
    # 1. First, get the auth token
    print("Logging in...")
    token = login(email, password)
    if not token:
        print("Failed to get authentication token")
        return
    
    print(f"\nAuthentication successful!")
    print(f"Token: {token[:20]}...")  # Print first 20 chars of token
    
    # 2. Now try to create a post
    content = "Testing post to social media"
    # You need to provide the actual platform IDs from your database
    # You can get these by checking your SelectedPlatform model
    platform_ids = [1, 2]  # Replace with actual platform IDs from your database
    
    print(f"\nPosting to platforms with IDs: {platform_ids}")
    response = create_post(token, content, platform_ids)
    
    if response:
        print(f"\nStatus Code: {response.status_code}")
        try:
            print("Response:", json.dumps(response.json(), indent=2))
        except:
            print("Response:", response.text)
    else:
        print("Failed to create post")

if __name__ == "__main__":
    main()