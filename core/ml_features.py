import os
import math

SUSPICIOUS_KEYWORDS = [
    b'powershell', b'cmd.exe', b'rundll32', b'base64', b'vbs', b'jscript', b'ftp', b'curl', b'wget', b'Invoke-', b'Add-MpPreference'
]

EXTENSIONS = ['exe', 'dll', 'bat', 'cmd', 'js', 'vbs', 'txt', 'jpg', 'png', 'pdf', 'doc', 'xls', 'zip', 'rar']

def file_entropy(path):
    try:
        with open(path, 'rb') as f:
            data = f.read()
        if not data:
            return 0.0
        occur = [0] * 256
        for b in data:
            occur[b] += 1
        entropy = 0.0
        for count in occur:
            if count:
                p = count / len(data)
                entropy -= p * math.log2(p)
        return entropy
    except:
        return 0.0

def extract_features(file_path):
    size = os.path.getsize(file_path)
    entropy = file_entropy(file_path)
    ext = os.path.splitext(file_path)[1][1:].lower()
    ext_feat = [1 if ext == e else 0 for e in EXTENSIONS]
    keyword_feat = [0]*len(SUSPICIOUS_KEYWORDS)
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            for i, kw in enumerate(SUSPICIOUS_KEYWORDS):
                if kw in content:
                    keyword_feat[i] = 1
    except:
        pass
    return [size, entropy] + ext_feat + keyword_feat 