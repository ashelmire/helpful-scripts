#!/usr/bin/python

import pefile
import os

def usage():
    print "peDumpRes.py fileWithResources"
    print "Will dump resources to filename.resname"

def dumRes(pe):
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        print "%s does not have .rsrc's" % (os.sys.argv[1])
        quit()

    count = 0
    resource_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries]
    for rsrc in resource_idx:
        data_rva = rsrc.directory.entries[0].data.struct.OffsetToData
        size = entry.directory.entries[0].data.struct.Size
        

        count += 1


def main():
    if len(os.sys.argv) == 2:
        pe = pefile.PE(os.sys.argv[1])
        dumpRes(pe)
    else:
        usage()

if __name__ == '__main__':
    main()
