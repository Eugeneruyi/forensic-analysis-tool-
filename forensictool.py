import hashlib  # it gives python access to the hashing algorithms and cryptographic hashing functions
import os  # it gives python access to the operating system functionality e.g file and directory manipulation

class FileHasher:#this is called a docstring for calculating hashes and to verify evidience # is responsible for hashing the files, computes crytographic hashes of files for evidence verification. rellife scenario:after collecting evidences, you hash it imediately ,if months later someone ask "is this the orginal file ?",just hash again and compare.
@staticmethod
def compute_hash(file_path, algorithm='sha256'):
    """
    Computes the hash of a file using the specified algorithm.

    calculate hash of a file in chunks to handle large files efficiently. It reads the file in chunks and updates the hash object with each chunk until the entire file is processed.
    why chunks: A 10Gb file does not fit in a RAM. we read it in 64kb pieces,and feed each to the hasher building the hash. 
    """
    chunk_size = 65536  # 64KB chunks
    hasher = hashlib.new(algorithm) # Read the file in 64Kb chuncks.
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest() # Return the hash as Hex string.
    except Exception as e:
        return f"Error:{str(e)}"


    
    