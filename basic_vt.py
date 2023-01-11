import hashlib
import requests
import json
import sys

def scan_file(file_path):
    API_KEY = "YOUR_API_KEY_HERE"
    url = "https://www.virustotal.com/vtapi/v2/file/report"

    with open(file_path, 'rb') as f:
        data = f.read()
        file_hash = hashlib.md5(data).hexdigest()

    params = {'apikey': API_KEY, 'resource': file_hash}
    response = requests.get(url, params=params)

    if response.status_code == 200:
        json_response = json.loads(response.text)
        if json_response["response_code"] == 1:
            if json_response["positives"] > 0:
                return (f"File {file_path} is known to be malicious")
            else:
                return (f"File {file_path} is not known to be malicious")
        else:
            return ("Error while scanning the file")
    else:
        return ("Error while scanning the file")

# Replace "path/to/file" with the actual path to the file you want to scan
print(scan_file(sys.argv[1]))

