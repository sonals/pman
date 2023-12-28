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
import os
import datetime
import pprint

PRIVATEDB = '~/Documents/encfsdata.d'
#PRIVATEDIR = '~/Private'
PRIVATEDIR = '/tmp'
PASSCSV = f'{PRIVATEDIR}/password.csv'

class PasswordManager:
    _SCHEMA = ['ORGANIZATION', 'URL', 'USERID', 'PASSWD', 'OTHERID1', 'OTHERID2', 'DATE', 'KIND', 'NOTES']

    def __init__(self, csvFileName = PASSCSV):
        self._csvFileName = csvFileName
        print(f"Initializing database from CSV file {self._csvFileName}")
        self._passwordTable = []
        with open(self._csvFileName, mode='r', encoding='utf8') as csvFileHandle:
            reader = csv.DictReader(csvFileHandle, delimiter=',', quoting=csv.QUOTE_MINIMAL)
            assert(reader.fieldnames == PasswordManager._SCHEMA)
            for row in reader:
                self._passwordTable.append(row)
        print(f"Found {len(self._passwordTable)} records")

    def _getUpdateCSVFileName(self):
        csvUpdateFileName = os.path.splitext(self._csvFileName)[0]
        csvUpdateFileName += '.'
        csvUpdateFileName += datetime.date.today().isoformat()
        csvUpdateFileName += '.csv'
        return csvUpdateFileName

    def writeUpdateTable(self):
        with open(self._getUpdateCSVFileName(), mode='w', encoding='utf8') as csvUpdateFileHandle:
            writer = csv.DictWriter(csvUpdateFileHandle, PasswordManager._SCHEMA, restval = None,
                                    delimiter=',', quoting=csv.QUOTE_MINIMAL)
            writer.writeheader()
            for row in self._passwordTable:
                writer.writerow(row)

    def extractOrg(self, orgName):
        pattern = re.compile(orgName, re.IGNORECASE)
        orgList = []
        for row in self._passwordTable:
            if (pattern.search(row['ORGANIZATION'])):
                orgList.append(row)
        return orgList


DATEFORMAT = ["%b %d, %y", "%m/%d/%y"]

def parseCommandLine(args):
    msg = "Lookup the password for the organization requested"
    parser = argparse.ArgumentParser(description = msg, exit_on_error = False)
    parser.add_argument('-o', '--org', dest = 'oname', nargs = 1, required=True)
    parser.add_argument('-u', '--update', dest = 'update', action='store_true')
    parser.add_argument('--file', default = PASSCSV, dest ='fname', metavar ='csvfile', nargs = 1)
    # strip out the argv[0]
    return parser.parse_args(args[1:])

def main(args):
    try:
        argtab = parseCommandLine(args)
        pm = PasswordManager(argtab.fname)
        rows = pm.extractOrg(argtab.oname[0])
        pp = pprint.PrettyPrinter(indent=4, sort_dicts=False)
        pp.pprint(rows)

        pm.writeUpdateTable();

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
