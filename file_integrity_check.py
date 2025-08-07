import hashlib
import os
import json

def generate_hash(file_path):
    """Generate SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return None

def create_hashes(directory, output_file="hashes.json"):
    """Generate and store hashes for all files in a directory."""
    hashes = {}
    for root, _, files in os.walk(directory):
        for name in files:
            file_path = os.path.join(root, name)
            rel_path = os.path.relpath(file_path, directory)
            file_hash = generate_hash(file_path)
            if file_hash:
                hashes[rel_path] = file_hash

    with open(output_file, "w") as f:
        json.dump(hashes, f, indent=4)
    print(f"[✓] Hashes saved to '{output_file}'.")

def verify_hashes(directory, hash_file="hashes.json"):
    """Verify current file hashes with stored hashes."""
    if not os.path.exists(hash_file):
        print("[!] Hash file not found.")
        return

    with open(hash_file, "r") as f:
        stored_hashes = json.load(f)

    modified_files = 0
    missing_files = 0
    ok_files = 0

    print("\n🔍 Verifying file integrity...\n")
    for rel_path, old_hash in stored_hashes.items():
        file_path = os.path.join(directory, rel_path)
        new_hash = generate_hash(file_path)
        if new_hash is None:
            print(f"[!] Missing file: {rel_path}")
            missing_files += 1
        elif new_hash != old_hash:
            print(f"[✗] File modified: {rel_path}")
            modified_files += 1
        else:
            print(f"[✓] File OK: {rel_path}")
            ok_files += 1

    print("\n📊 Summary:")
    print(f"✔  OK files: {ok_files}")
    print(f"✗  Modified files: {modified_files}")
    print(f"❌ Missing files: {missing_files}")

def main():
    print("\n=== 🔐 File Integrity Checker ===")
    print("1. Generate file hashes")
    print("2. Verify file integrity")
    choice = input("Choose an option (1 or 2): ")

    directory = input("Enter directory path: ").strip()
    hash_file = input("Enter hash file name (default: hashes.json): ").strip()
    if not hash_file:
        hash_file = "hashes.json"

    if choice == "1":
        create_hashes(directory, hash_file)
    elif choice == "2":
        verify_hashes(directory, hash_file)
    else:
        print("Invalid choice.")

if _name_ == "_main_":
    main()
