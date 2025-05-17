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
        print(f"Attempting login with email: {email}")
        response = requests.post(url, json=data)
        print(f"Login response status: {response.status_code}")
        
        if response.status_code == 200:
            response_data = response.json()
            token = response_data.get('token')
            if token:
                print("Successfully obtained authentication token")
                return token
            else:
                print("No token in response. Full response:", response_data)
        else:
            print(f"Login failed: {response.status_code} - {response.text}")
        return None
    except Exception as e:
        print(f"Error during login: {str(e)}")
        return None

def check_platform_credentials(token, platform_name):
    """Check if user has credentials for the specified platform"""
    url = f"{BASE_URL}check-credentials/"
    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json"
    }
    params = {
        "platform": platform_name
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json().get('has_credentials', False)
        print(f"Error checking {platform_name} credentials: {response.text}")
        return False
    except Exception as e:
        print(f"Error checking {platform_name} credentials: {str(e)}")
        return False

def create_post(token, content, platforms):
    """Create a post on selected platforms"""
    url = f"{BASE_URL}social/post/"
    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json"
    }
    data = {
        "content": content,
        "platforms": platforms,
        "enable_likes": True,
        "enable_comments": True
    }
    try:
        print(f"\nSending post request to: {url}")
        print(f"Platforms: {platforms}")
        
        response = requests.post(url, headers=headers, json=data)
        return response
    except Exception as e:
        print(f"Error creating post: {str(e)}")
        return None

def main():
    # User credentials - UPDATE THESE
    email = "shaikhsharim7@gmail.com"
    password = "YOUR_CORRECT_PASSWORD"  # Replace with your actual password
    
    print("Logging in...")
    token = login(email, password)
    if not token:
        print("Failed to get authentication token")
        return
    
    print(f"\nAuthentication successful!")
    print(f"Token: {token[:20]}...")
    
    # Check available platforms and their credentials
    platforms_to_post = []
    available_platforms = [
        ("linkedin", 1),
        ("facebook", 2),
        ("instagram", 3)
    ]
    
    print("\nChecking platform credentials...")
    for platform_name, platform_id in available_platforms:
        if check_platform_credentials(token, platform_name):
            platforms_to_post.append(platform_id)
            print(f"✓ {platform_name.capitalize()} credentials found")
        else:
            print(f"✗ No credentials found for {platform_name}")
    
    if not platforms_to_post:
        print("\nNo platforms with valid credentials found.")
        return
    
    # Create post
    content = "Testing post to social media"
    print(f"\nPosting to platforms with IDs: {platforms_to_post}")
    response = create_post(token, content, platforms_to_post)
    
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