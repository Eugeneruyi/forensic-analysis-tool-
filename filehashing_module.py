import hashlib  # it gives python access to the hashing algorithms and cryptographic hashing functions
import os  # it gives python access to the operating system functionality e.g file and directory manipulation


class FileHasher:
    """
    This class is responsible for hashing files and computing cryptographic hashes 
    of files for evidence verification.
    
    Real life scenario: After collecting evidence, you hash it immediately. If months 
    later someone asks "is this the original file?", just hash again and compare.
    """
    
    @staticmethod
    def calculate_hash(file_path, algorithm='sha256'):
        """
        Computes the hash of a file using the specified algorithm.
        
        Calculate hash of a file in chunks to handle large files efficiently. 
        It reads the file in chunks and updates the hash object with each chunk 
        until the entire file is processed.
        
        Why chunks: A 10GB file does not fit in RAM. We read it in 64KB pieces 
        and feed each to the hasher, building the hash.
        """
        chunk_size = 65536  # 64KB chunks
        hasher = hashlib.new(algorithm)  # Create hash object with specified algorithm
        
        try:
            with open(file_path, 'rb') as f:  # 'rb' mode reads file in binary mode, which is important for hashing files accurately, especially for non-text files
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    hasher.update(chunk)
            return hasher.hexdigest()  # Return the hash as hex string
            
        except Exception as e:
            return f"Error: {str(e)}"

    @staticmethod
    def verify_file_integrity(file_path, known_hash):
        """
        Compares a file's current hash with a previously recorded hash to verify integrity.
        
        Real life scenario: You collected "malware.exe" on Sept 1st with hash "abc123". 
        On Dec 1st you hash it again. If hash matches, it hasn't been modified. 
        If it fails, someone has tampered with it.
        """
        current_hash = FileHasher.calculate_hash(file_path)
        return current_hash == known_hash, current_hash  # Return tuple: (match_status, current_hash)


# Test it
if __name__ == "__main__":
    # Let's create a test file and calculate its hash
    test_file = "/tmp/test_evidence.txt"
    
    with open(test_file, 'w') as f:  # Create a test file
        f.write("This is sensitive evidence")
    
    # Hash it
    hash1 = FileHasher.calculate_hash(test_file)
    print(f"Original hash: {hash1}")
    
    # Modify the file
    with open(test_file, 'a') as f:
        f.write("\nModified")
    
    # Hash again
    hash2 = FileHasher.calculate_hash(test_file)
    print(f"Modified hash: {hash2}")
    print(f"Same file? {hash1 == hash2}")  # False - proves modification