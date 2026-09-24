import os
import time
from datetime import datetime
from pathlib import Path

class MetadataExtractor:
    """
    Extract file metadata for forensic analysis.
    Real scenario: After collecting evidence, extract metadata for analysis and documentation.
    Example:
        metadata: "Finance Department"
        created: jan 2023
        modified: sept 2024 (2 hours before the breach was discovered)
        file size: 150mb (suspicious - should be 2mb)
    This tells the investigator the file was modified right before the attack.
    """
    
    @staticmethod
    def extract_file_metadata(file_path):
        """Extract comprehensive metadata from a single file."""
        try:
            file_stats = os.stat(file_path)
            created_time = datetime.fromtimestamp(file_stats.st_ctime)
            modified_time = datetime.fromtimestamp(file_stats.st_mtime)
            accessed_time = datetime.fromtimestamp(file_stats.st_atime)
            
            metadata = {
                'file_path': file_path,
                'file_name': os.path.basename(file_path),
                'file_size_bytes': file_stats.st_size,
                'file_size_mb': round(file_stats.st_size / (1024 * 1024), 2),
                'created_datetime': created_time.isoformat(),
                'modified_datetime': modified_time.isoformat(),
                'accessed_datetime': accessed_time.isoformat(),
                'modified_timestamp': file_stats.st_mtime,  # Add timestamp for comparisons
                'owner_uid': file_stats.st_uid,
                'owner_gid': file_stats.st_gid,
                'permissions_octal': oct(file_stats.st_mode)[-3:],
                'is_hidden': os.path.basename(file_path).startswith('.'),
                'is_symlink': os.path.islink(file_path)
            }
            
            # Add forensic analysis
            metadata['forensic_flags'] = MetadataExtractor.flag_suspicious(metadata)
            return metadata
            
        except Exception as e:
            return {'error': str(e), 'file_path': file_path}
    
    @staticmethod
    def flag_suspicious(metadata):
        """
        Flag potentially suspicious patterns.
        Real scenario: 
        - Hidden files (start with .)
        - Recently modified files during breach window
        - Files with unusual permissions (executable and hidden)
        - Very large files
        """
        flags = []
        
        if metadata['is_hidden']:
            flags.append("HIDDEN_FILE")
        
        # Check if recently modified (last 7 days)
        days_since_modified = (time.time() - metadata['modified_timestamp']) / 86400
        if days_since_modified < 7:
            flags.append("RECENTLY_MODIFIED")
        
        # Large file + recently modified = possible exfiltration
        if metadata['file_size_mb'] > 100 and days_since_modified < 7:
            flags.append("LARGE_RECENT_FILE_SUSPICIOUS")
        
        # Check for world-readable sensitive files
        if metadata['permissions_octal'] in ['644', '666', '777']:
            flags.append("WORLD_READABLE")
        
        return flags


# Test it
if __name__ == "__main__":
    test_file = "/etc/passwd"  # Use a system file for testing
    
    metadata = MetadataExtractor.extract_file_metadata(test_file)
    
    print("\n===FILE METADATA===")
    for key, value in metadata.items():
        print(f"{key}: {value}")