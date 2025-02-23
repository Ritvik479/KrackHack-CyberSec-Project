import hashlib
from app import re
def calculate_file_hash(file_path):
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Error calculating hash for {file_path}: {e}")
        return None

def check_is_malicious(file_path, known_hashes):
    try:
        file_hash = calculate_file_hash(file_path)
        
        if file_hash in known_hashes:
            print(f"[ALERT] {file_path} is malicious (Hash match found)!")
            return True
        else:
            print(f"[SAFE] {file_path} appears to be clean.")
    except Exception as e:
        print(f"Error scanning {file_path}: {e}")

def check_file(file_to_scan):
    counter = 1
    while counter <= 6:
        file_ = open(f"Malware-Hash-Database\\SHA256\\sha256_hashes_{counter}.txt","r")
        if check_is_malicious(file_to_scan, file_.read() ):
            return True
        counter += 1
        file_.close()
    return False