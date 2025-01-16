import hashlib
import os

def calculate_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def monitor_changes(directory):
    """Monitor changes in files within a directory by comparing hash values."""
    file_hashes = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hashes[file_path] = calculate_hash(file_path)
    
    while True:
        for file_path, old_hash in file_hashes.items():
            if os.path.exists(file_path):
                new_hash = calculate_hash(file_path)
                if new_hash != old_hash:
                    print(f"File changed: {file_path}")
                    file_hashes[file_path] = new_hash
            else:
                print(f"File deleted: {file_path}")
                del file_hashes[file_path]
        
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if file_path not in file_hashes:
                    print(f"New file added: {file_path}")
                    file_hashes[file_path] = calculate_hash(file_path)

if __name__ == "__main__":
    directory_to_monitor = "/path/to/your/directory"
    monitor_changes(directory_to_monitor)
