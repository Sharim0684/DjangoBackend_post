import requests

url = "http://127.0.0.1:8000/api/linkedin_api/post/"
headers = {"Content-Type": "application/json"}
data = {
    "access_token": "AQUSHDoC52WeUY2NF-U7FXa-_gYyLIS39sx2HW2tF_7yaL3DFRQFq1iLUGeS0OUmT1_hT5mp99XQU9LsR7Q3SrjtZUvPkDQ-WzVWdU6-6ZYfcHkHto7v8eHZwKsC-UQ2tg6KNJkaUft4mBfyWQWSpLeUIaIuWZh9HD31QeCFr6QGmREu1-LvpoKknkQ9PZWPaWrxmKZroJ76lMCaQkU5R7fktOQfeX3ez1Rvj-iTWLeQqr_6vl4xUoWZoY_OYTfU5YJ4pQTQieE5uDNvgitYZvlYDKZwu53hUjDganligTzxR3BXKuu325WVBNj0kVwARwVxcazVFgxTEmsKwW55cdK-MVztsQ",
    "message": "HII",
    "visibility": "PUBLIC"
}

response = requests.post(url, json=data, headers=headers)
print(response.json())