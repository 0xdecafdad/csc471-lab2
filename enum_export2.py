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

# implement better sorting algorithm later
def insertion_sort(ary):
    # traverse through ary from index 1 to length
    for i in range(1, len(ary)):
        key = ary[i]

        # move elements greater than key one position ahead
        j = i-1
        while j >= 0 and key < ary[j]:
            ary[j+1] = ary[j]
            j -= 1
        ary[j+1] = key
# end insertion_sort()

def main():
    # maybe add default if no argument is provided, or at least prevent crash
    malware_path = sys.argv[1] # path to directory with malware

    # add try/catch block in case of invalid path
    malware_dir = os.scandir(malware_path) # returns list of os.DirEntry objects

    # accesses each file in directory
    for malware_file in malware_dir:
        pe = pefile.PE(malware_file)

        # keys = memory address; value = number of occurences in file
        rule1 = {} # dictionary

        # keys = offset; value = number of occurences in file
        rule2 = {} # dictionary

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            # loops through address for each function in current file
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                function_address = (hex(exp.address + pe.OPTIONAL_HEADER.ImageBase))
                # rule 1: checks if function exists, if not, add it to dic
                if function_address in rule1:
                    rule1[function_address] += 1
                else:
                    rule1[function_address] = 1
            # end of inner for loop

        # rule1.keys() is a list of all memory addresses in file (one of each) as strings
        # converts all addresses from string to int (for arithmetic)
        addr_as_hex = [int(addr, 16) for addr in rule1.keys()] # Haskell lol
        insertion_sort(addr_as_hex) # sort array

        # calculate memory offset between two functions
        # add value to dict if it does not exist already
        # otherwise, add one to its value
        for i in range(1, len(addr_as_hex)):
                offset = addr_as_hex[i] - addr_as_hex[i-1]
                
                if offset in rule2:
                    rule2[offset] += 1
                else:
                    rule2[offset] = 1

        # determines if current file is malware based on parameters stated earlier
        # initially assumes neither rule is violated
        rule1_violated = False
        rule2_violated = False

        # check for violation of rule 1
        for num_occur_addr in rule1.values():
            # three or more functions share the same memory address
            if num_occur_addr >= 3:
                rule1_violated = True

        # check for violation of rule 2
        for num_occur_offset in rule2.values():
            # memory offset between three or more functions is the same
            if num_occur_offset >= 3:
                rule2_violated = True

        # if either rule was violated, file is flagged as malware
        if rule1_violated or rule2_violated:
            print("%s: Malware detected!" % malware_file.name)
        else:
            print("%s: No malware detected." % malware_file.name)

        if rule1_violated:
            print("\t%s" % "(Rule 1) Three or more functions share the same memory address.")

        if rule2_violated:
            print("\t%s" % "(Rule 2) Memory offset between three or more functions is the same.")

        print("") # print new line

        rule1.clear() # clears dictionary for next file
        rule2.clear() # clears dictionary for next file
    # end of outer for loop
# end main function

if __name__=="__main__":
    main()
