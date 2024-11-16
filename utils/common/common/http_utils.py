import requests

def fetch_json(url: str):
    response = requests.get(url)
    response.raise_for_status()
    return response.json()

