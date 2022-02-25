# Author(s): Shaun Derstine
# Date: 2/24/2022
# Desc: Given a path to a directory containing PE files, this program determines if
#       each file is a malware based on two heuristic rules
#       
#       Rule 1: Three or more export functions share the same memory address
#       Rule 2: Three or more export functions have the same memory offset

import pefile
import sys
import os

# maybe add default if no argument is provided, or at least prevent crash
malware_path = sys.argv[1] # path to directory with malware

# add try/catch block in case of invalid path
malware_dir = os.scandir(malware_path) # returns list of os.DirEntry objects

# accesses each file in directory
for malware_file in malware_dir:
    pe = pefile.PE(malware_file)

    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print("%s" % (hex(exp.address + pe.OPTIONAL_HEADER.ImageBase)))
            # end of inner for loop
    print("\n")
    # end of outer for loop
