import hashlib

def calculate_file_hash(file_path):
    """Calculate SHA256 hash of the file located at file_path."""
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Error calculating hash for {file_path}: {e}")
        return None

def file_check(file_to_scan):
    """
    Check if the file at file_to_scan is malicious by comparing its hash
    against known malicious hashes stored in multiple files.
    Returns True if malicious, otherwise False.
    """
    file_hash = calculate_file_hash(file_to_scan)
    if file_hash is None:
        return False  # If hash couldn't be computed, consider it not malicious

    # Iterate over the known hash files
    for counter in range(1, 7):
        hash_file_path = f"Malware-HashFiles/SHA256/sha256_hashes_{counter}.txt"
        try:
            with open(hash_file_path, "r") as f:
                # Read each line, stripping whitespace; assume one hash per line.
                known_hashes = {line.strip() for line in f if line.strip()}
            if file_hash in known_hashes:
                print(f"[ALERT] {file_to_scan} is malicious (Hash match found)!")
                return True
            else:
                print(f"[SAFE] {file_to_scan} does not match hashes in {hash_file_path}.")
        except Exception as e:
            print(f"Error reading {hash_file_path}: {e}")
    return False
