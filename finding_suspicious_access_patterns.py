#it identifies files accessed unusual ways.
#Real life scenario: Attacker typically access files in patterns:
# Rapid sequential access (copying data)
# Access from unusual time(3 Am)
# Pattern changes(normal 9-5 to suddenly)

import datetime

class AccessPatternAnalyzer:
    """
    Analyzes file access patterns to detect suspicious behavior.
    Real scenario: Normal users login by 8 AM, works 9 - 5 , logs out by 6 PM
    One Day: Access logs show activity at 2AM  accessing finance directory .
    Red Flag: Probably compromised.
    """
    
@staticmethod
def analyze_access_patterns(evidence_collection):
    """
    Analyze access patterns across collected evidence
    """
    
    analysis = {
        'by_hour': {},
        'by_date': {},
        'suspicious_patterns': []
    }
    
    for entry in evidence_collection:
        #Extract hour from modified time
        modified_time = datetime.fromisoformat(entry['modified_datetime'])
        hour = modified_time.hour()
        date_key = modified_time.date().isoformat()
        
        # count by hour
        analysis['by_hour'][hour] = analysis['by_hour'].get(hour, 0) + 1
        
        #count by date
        analysis['by_date'][date_key] = analysis['by_date'].get(date_key, 0) + 1
        
    # Detect unusual hours 
    if hour in [0, 1, 2, 3, 4, 5]: #midnight to 5AM
        if entry['file_size_mb'] > 10: # large file
            analysis['suspicious_patterns'].append({
                'file': entry['file_path'],
                "reason": f'Large file({entry["file_size_mb"]} MB)' modified at {hour}:00',
                'severity': 'HIGH'
            })
            
    return analysis
    
# Test combined flow
if __name__ == "__main__":
    print("\n=== ACCESS PATTERN ANALYSIS ===")
    patterns = AccessPatternAnalyzer.analyze_access_patterns(scanner.evidence_collection)