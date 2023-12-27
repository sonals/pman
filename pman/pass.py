#!/usr/bin/env python3
#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 sonal.santan@gmail.com
#

"""
This is a encfs based password manager written in python

"""

import argparse
import sys
import csv
import re
import pprint

PRIVATEDB = '~/Documents/encfsdata.d'
#PRIVATEDIR = '~/Private'
PRIVATEDIR = '/tmp'
PASSCSV = f'{PRIVATEDIR}/password.csv'

DATEFORMAT = ["%b %d, %y", "%m/%d/%y"]

SCHEMA = ['ORGANIZATION', 'URL', 'USERID', 'PASSWD', 'OTHERID1', 'OTHERID2', 'DATE', 'KIND', 'NOTES']

def parseCommandLine(args):
    msg = "Lookup the password for the organization requested"
    parser = argparse.ArgumentParser(description = msg, exit_on_error = False)
    parser.add_argument('-o', '--org', dest = 'oname', nargs = 1, required=True)
    parser.add_argument('-u', '--update', dest = 'update', action='store_true')
    parser.add_argument('--file', default = PASSCSV, dest ='fname', metavar ='csvfile', nargs = 1)
    # strip out the argv[0]
    return parser.parse_args(args[1:])

def extractOrg(passTab, orgName):
    pattern = re.compile(orgName, re.IGNORECASE)
    orgList = []
    for row in passTab:
        if (pattern.search(row['ORGANIZATION'])):
            orgList.append(row)
    return orgList

def parseCSV(csvName, orgName):
    with open(csvName, mode='r', encoding='utf8') as csvFile:
        pp = pprint.PrettyPrinter(indent=4, sort_dicts=False)
        passTab = csv.DictReader(csvFile, delimiter=',', quoting=csv.QUOTE_MINIMAL)
        assert(passTab.fieldnames == SCHEMA)
        pp.pprint(passTab.fieldnames)
        rows = extractOrg(passTab, orgName)
        pp.pprint(rows)

def main(args):
    try:
        argtab = parseCommandLine(args)
        print(f"Using CSV file {argtab.fname} as data base")
        parseCSV(argtab.fname, argtab.oname[0])
#        extractOrg(passTab, argtab.oname[0])
        return 0
    except OSError as o:
        print(o)
        return o.errno
    except AssertionError as a:
        print(a)
        return 1
    except Exception as e:
        print(e)
        return 1

if __name__ == '__main__':
    RESULT = main(sys.argv)
    sys.exit(RESULT)
