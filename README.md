# csc471-lab2
Heuristic malware detection system

This program scans a directory for pe files and determines if each is a malware using a set of heuristical rules

Rule 1:
Three or more export functions share the same memory address

Rule 2:
Three or more export functions have the same memory offset

Notes:
All malware is in the form of a PE file. I included all malware in one folder because program does not check for file type. Program will crash if incorrect file type is included.

Use:
python3 enum_export.py path_to_directory_with_malware

Files:
analyze_malware.py
Analyze all malware in specified directory.

enum_export.py
Output PE structure of individual file.

malware
Directory containing malware files.
