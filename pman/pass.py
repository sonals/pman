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
    """
    A simple command line based password manager. The passwords are stored in a CSV file
    with the schema defined by _SCHEMA.
    TODO: Support for encrypting the password file
    """
    _SCHEMA = ['ORGANIZATION', 'URL', 'USERID', 'PASSWD', 'OTHERID1', 'OTHERID2', 'DATE',
               'KIND', 'NOTES']

    def __init__(self, csv_file_name = PASSCSV):
        """ PasswordManager class constructor """
        self._csv_file_name = csv_file_name
        print(f"Initializing database from CSV file {self._csv_file_name}")
        self._password_table = []
        with open(self._csv_file_name, mode='r', encoding='utf8') as csv_file_handle:
            reader = csv.DictReader(csv_file_handle, delimiter=',', quoting=csv.QUOTE_MINIMAL)
            assert(reader.fieldnames == PasswordManager._SCHEMA)
            for row in reader:
                self._password_table.append(row)
        print(f"Found total {len(self._password_table)} records in the database")

    def _get_update_csv_file_name(self):
        """ Generate time indexed csv file name to store the updated database """
        csv_update_file_name = os.path.splitext(self._csv_file_name)[0]
        csv_update_file_name += '.'
        csv_update_file_name += datetime.date.today().isoformat()
        csv_update_file_name += '.csv'
        return csv_update_file_name

    def write_update_table(self):
        """ Write out the updated databse to the new csv file """
        with open(self._get_update_csv_file_name(), mode='w',
                  encoding='utf8') as csv_update_file_handle:
            writer = csv.DictWriter(csv_update_file_handle, PasswordManager._SCHEMA,
                                    restval = None, delimiter=',', quoting=csv.QUOTE_MINIMAL)
            writer.writeheader()
            for row in self._password_table:
                writer.writerow(row)

    def extract_org(self, org_name):
        """ Look up the record(s) with matching org name """
        pattern = re.compile(org_name, re.IGNORECASE)
        org_list = []
        for row in self._password_table:
            if (pattern.search(row['ORGANIZATION'])):
                org_list.append(row)
        return org_list

    def ask_user_and_update(self, row):
        """ Ask the user to provide updated record fields for a org """
        response = "no"
        while (response != "yes"):
            for key in list(row):
                value = input(f"{key}: [{row[key]}] ")
                if (len(value)):
                    row[key] = value
            pretty = pprint.PrettyPrinter(indent=4, sort_dicts=False)
            pretty.pprint(row)
            response = input("Commit the above to the database? [yes/no] ")

    def update_org(self, org_name):
        """ Either update an exisiting record or create a new record and commit to the database """
        org_list = self.extract_org(org_name)
        row = None
        if (len(org_list) > 1):
            raise RuntimeError(f"Error: found more than one record with {org_name}")
        if (len(org_list) == 1):
            row = org_list[0]
        else:
            values = ['None'] * len(PasswordManager._SCHEMA)
            row = dict((zip(PasswordManager._SCHEMA, values)))
            row['ORGANIZATION'] = org_name
            row['DATE'] = datetime.date.today().isoformat()
            self._password_table.append(row)
        self.ask_user_and_update(row)

def parse_command_line(args):
    """ Command line parsing helper routine """
    msg = "Lookup the password for the organization requested"
    parser = argparse.ArgumentParser(description = msg, exit_on_error = False)
    parser.add_argument('-o', '--org', dest = 'oname', nargs = 1, required=True)
    parser.add_argument('-u', '--update', dest = 'update', action='store_true')
    parser.add_argument('--file', default = PASSCSV, dest ='fname', metavar ='csvfile', nargs = 1)
    # strip out the argv[0]
    return parser.parse_args(args[1:])

def main(args):
    """ Main entry point function """
    try:
        argtab = parse_command_line(args)
        pman = PasswordManager(argtab.fname)
        rows = pman.extract_org(argtab.oname[0])
        pretty = pprint.PrettyPrinter(indent=4, sort_dicts=False)
        pretty.pprint(rows)

        if (argtab.update):
            pman.update_org(argtab.oname[0])
            pman.write_update_table()
        return 0

    except OSError as oerr:
        print(oerr)
        return oerr.errno
    except AssertionError as aerr:
        print(aerr)
        return 1
    except Exception as eerr:
        print(eerr)
        return 1

if __name__ == '__main__':
    RESULT = main(sys.argv)
    sys.exit(RESULT)
