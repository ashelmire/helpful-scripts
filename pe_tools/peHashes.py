#!/usr/bin/env python

import pefile
import sys
import time

def usage():
    print "peHashes.py <PEfile>"
    print "Prints the PE's date, sections, section hashes, and imphash"

def main(pe):
    date = pe.FILE_HEADER.TimeDateStamp
    buildDate = time.strftime("%a-%d/%m/%Y+%H:%M:%S", time.gmtime(date))
    print buildDate

    for section in pe.sections:
        print section.Name
        print section.get_hash_md5()

    imphash = pe.get_imphash()
    print imphash


if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
    elif len(sys.argv) == 2:
        try:
          pe = pefile.PE(sys.argv[1])
          main(pe)
        except:
          print "not a PE"

