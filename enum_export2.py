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

    # keys = memory address; value = number of occurences in file
    rule1 = {}

    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        # prints out address for each function in current file
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            # for finding address of function: (hex(exp.address + pe.optional_header.imagebase))
            function_address = (hex(exp.address + pe.OPTIONAL_HEADER.ImageBase))
            if function_address in rule1:
                rule1[function_address] += 1
            else:
                rule1[function_address] = 1
            # end of inner for loop

    # determines if current file is malware based on parameters stated earlier
    is_malware = False

    # check for rule 1
    for value in rule1.values():
        if value >= 3:
            is_malware = True

    # print message based on whether or not malware was detected
    if is_malware == True:
        print("%s: Malware detected!" % malware_file.name)
    else:
        print("%s: No malware detected." % malware_file.name)
    rule1.clear() # clears dictionary for next file
    # end of outer for loop
