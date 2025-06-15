import requests
import configparser
import os

def get_api_key():
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config.get('virustotal', 'api_key', fallback=None)

def check_hash_virustotal(file_hash):
    api_key = get_api_key()
    if not api_key:
        return None
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {'x-apikey': api_key}
    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            stats = data['data']['attributes']['last_analysis_stats']
            total = sum(stats.values())
            detected = stats.get('malicious', 0) + stats.get('suspicious', 0)
            permalink = data['data']['links']['self']
            return {
                'detected': detected,
                'total': total,
                'permalink': permalink,
                'stats': stats
            }
        elif resp.status_code == 404:
            return {'not_found': True}
        else:
            return None
    except Exception as e:
        print(f'Error VirusTotal: {e}')
        return None

def upload_file_virustotal(file_path):
    api_key = get_api_key()
    if not api_key:
        return None
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {'x-apikey': api_key}
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            resp = requests.post(url, headers=headers, files=files)
        if resp.status_code == 200 or resp.status_code == 202:
            data = resp.json()
            analysis_id = data['data']['id']
            return f'https://www.virustotal.com/gui/file/{analysis_id}/detection'
        else:
            print(f'Upload VirusTotal not found: {resp.status_code} {resp.text}')
            return None
    except Exception as e:
        print(f'Error upload VirusTotal: {e}')
        return None 