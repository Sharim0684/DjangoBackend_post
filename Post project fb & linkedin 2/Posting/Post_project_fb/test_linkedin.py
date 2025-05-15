import requests

def test_linkedin_post():
    url = "http://localhost:8000/social"
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "linkedin": {
            "message": "Test post from LinkedIn API"
        }
    }
    
    try:
        response = requests.post(url, json=data, headers=headers)
        print("Status Code:", response.status_code)
        print("Response:", response.text)
        
        if response.status_code == 200:
            print("Post successful!")
            return response.json()
        else:
            print("Error posting to LinkedIn")
            return None
            
    except Exception as e:
        print(f"Error: {str(e)}")
        return None

if __name__ == "__main__":
    # Make sure the FastAPI server is running first
    result = test_linkedin_post()
    if result:
        print("Result:", result)