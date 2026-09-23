import hashlib  # it gives python access to the hashing algorithms and cryptographic hashing functions
import os  # it gives python access to the operating system functionality e.g file and directory manipulation

class FileHasher:#this is called a docstring for calculating hashes and to verify evidience # is responsible for hashing the files, computes crytographic hashes of files for evidence verification. rellife scenario:after collecting evidences, you hash it imediately ,if months later someone ask "is this the orginal file ?",just hash again and compare.
@staticmethod
def calculate_hash(file_path, algorithm='sha256'):
    """
    Computes the hash of a file using the specified algorithm.

    calculate hash of a file in chunks to handle large files efficiently. It reads the file in chunks and updates the hash object with each chunk until the entire file is processed.
    why chunks: A 10Gb file does not fit in a RAM. we read it in 64kb pieces,and feed each to the hasher building the hash. 
    """
    chunk_size = 65536  # 64KB chunks
    hasher = hashlib.new(algorithm) # Read the file in 64Kb chuncks.
    try:
        with open(file_path, 'rb') as f: # 'rb ' mode is used to read the file in binary mode, which is important for hashing files accurately, especially for non-text files.
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest() # Return the hash as Hex string.
    except Exception as e:
        return f"Error:{str(e)}"

@staticmethod
def verify_file_intergrity(file_path, known_hash):
    """
    compares a file's current hash witha previously recorded hash to verify it's integrity.
    Real life scenario: you collected "malware.exe" on sept 1st with hash "abc123" and on Dec 1st you hash it again if hash matches it has'nt be modified but if it fails someone has tempered with it.
    """
    current_hash = FileHasher.calculate_hash(file_path)
    return current_hash == known_hash, current_hash  # Return a tuple indicating whether the hashes match and the current hash value.


# Test it
if __name__== "__main__":
    # Let's create a test file and calculate its hash
    test_file = "/tmp/test_evidence.txt"
    with open(test_file, 'w') as f:
        f.write("This is sensitive evidences")

    # Hash it
    hash1 = FileHasher.calculate_hash(test_file)
    print(f"Original hash: {hash1}")

    # modify the file
    with open(test_file, 'a') as f:
        f.write("\nModified")

    # Hash again
    hash2 = FileHasher.calculate_hash(test_file)
    print(f"Modified hash: {hash2}")
    print(f" same file? {hash1 == hash2}") # False - proves modification
    