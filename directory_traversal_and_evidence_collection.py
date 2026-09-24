import os
class ForensicScanner:
    """
    Traverses file system and collects evidence systematically.
    It is like documenting a physical crime scence:
    photograph everything
    Note locations
    collect all evidence systmatically
    create an inventry
    """
# The constructor(__int__)

def __init__(self, output_log_file="forensic_evidence.log"): # constructor to initialize the ForensicScanner class with an output log file
    self.output_log_file = output_log_file   # Initialize the output log file, it stores file name in the object
    self.evidence_collection = [] # Initialize an empty list to store collected evidence metadata each time will scan a directory

def scan_directory(self,root_path, include_hidden = False, max_depth=None, date_range=None):
    """
    Recursively scans a directory for files and collects evidence.
    
    Parameters:
        root_path (str): The root directory to start scanning.
        include_hidden (bool): Whether to include hidden files in the scan.
        max_depth (int): Maximum depth to traverse. None means no limit.
        date_range (tuple): A tuple of (start_date, end_date) to filter files by modification date.
        
        Real scenario:
        scan_directory(
        '/home/john/'
        date_range=(1726588800, 1726761600) # sept 17-19, 2024 )
        Returns onlt modified files in that window
        """

    for root, dirs, files in os.walk(root_path):
        #control recursion  depth
        if max_depth is not None:
            current_depth = root.replace(root_path, '').count(os.sep)
            if not include_hidden and filename.startwith('.'):
                continue



    



