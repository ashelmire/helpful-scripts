#!/usr/bin/env python

import pefile
import sys
import time

def usage():
    print "peBuildDate.py <PEfile>"
    print "Prints the peFiles buildd ate in day-DD/MM/YYYY+HH:MM:SS format"

def main(pe):
    date = pe.FILE_HEADER.TimeDateStamp
    buildDate = time.strftime("%a-%d/%m/%Y+%H:%M:%S", time.gmtime(date))
    print buildDate

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
    elif len(sys.argv) == 2:
        try:
          pe = pefile.PE(sys.argv[1])
          main(pe)
        except:
          print "not a PE"

