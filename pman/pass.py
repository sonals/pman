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
import csv
import datetime
import getpass
import os
import pprint
import re
import readline
import shutil
import sys
import urllib.parse

#PRIVATEDB = '~/Documents/encfsdata.d'
#PRIVATEDIR = '~/Private'
PRIVATEDIR = '/tmp'

class PasswordManager:
    """
    A simple command line based password manager. The passwords are stored in a CSV file
    with the schema defined by _SCHEMA.
    TODO: Support for encrypting the password file
    """
    _SCHEMA = ['ORGANIZATION', 'URL', 'USERID', 'PASSWD', 'OTHERID1', 'OTHERID2', 'DATE',
               'KIND', 'NOTES']
    _PASSCSV = 'password.csv'
    _BACKUPDIR = 'backup.d'

    def __init__(self, root_dir = PRIVATEDIR):
        """ PasswordManager class constructor """
        self._csv_file_name = f'{root_dir}/{PasswordManager._PASSCSV}'
        self._pretty = pprint.PrettyPrinter(indent=4, sort_dicts=False)
        print(f"Initializing database from CSV file {self._csv_file_name}...")
        self._password_table = []
        with open(self._csv_file_name, mode='r', encoding='utf8') as csv_file_handle:
            reader = csv.DictReader(csv_file_handle, delimiter=',', quoting=csv.QUOTE_MINIMAL)
            assert(reader.fieldnames == PasswordManager._SCHEMA)
            for row in reader:
                self._password_table.append(row)
        print(f"Total {len(self._password_table)} records found")

    def _get_backup_csv_file_name(self):
        """ Generate date indexed CSV file name to backup the database """
        base_ext = os.path.splitext(PasswordManager._PASSCSV)
        csv_backup_file_name = os.path.dirname(self._csv_file_name)
        csv_backup_file_name += f'/{PasswordManager._BACKUPDIR}'
        csv_backup_file_name += f'/{base_ext[0]}'
        csv_backup_file_name += '.'
        csv_backup_file_name += datetime.date.today().isoformat()
        csv_backup_file_name += f'{base_ext[1]}'
        return csv_backup_file_name

    def write_updated_table(self):
        """ Write out the updated database to the CSV file """
        with open(self._csv_file_name, mode='w',
                  encoding='utf8') as csv_update_file_handle:
            writer = csv.DictWriter(csv_update_file_handle, PasswordManager._SCHEMA,
                                    restval = None, delimiter=',', quoting=csv.QUOTE_MINIMAL)
            writer.writeheader()
            for row in self._password_table:
                writer.writerow(row)
        print(f"Committed {len(self._password_table)} records to the CSV file {self._csv_file_name}")

    def extract_record(self, org_name):
        """ Look up the record indices with matching org name """
        pattern = re.compile(org_name, re.IGNORECASE)
        org_list = []
        index = 0
        for row in self._password_table:
            if (pattern.search(row['ORGANIZATION'])):
                org_list.append(index)
            index += 1
        return org_list

    def _ask_user_and_update_record(self, index):
        """ Ask the user to provide updated fields for the specified record """
        row = self._password_table[index]
        response = "no"
        self.print_record(index)
        response = input(f"Update record INDEX {index} for organization {row['ORGANIZATION']} [yes/no]? ")
        if (response == "no"):
            return
        response = "no"
        while (response != "yes"):
            for key in list(row):
                prompt = f"{key}: [{row[key]}] "
                match key:
                    case 'URL':
                        value = input(prompt)
                        # Validate the URL
                        urllib.parse.urlparse(value)
                    case 'PASSWD':
                        value = getpass.getpass(prompt)
                    case _:
                        value = input(prompt)

                if (len(value)):
                    row[key] = value

            self.print_record(index)
            response = input("Commit the above to the database? [yes/no] ")

    def update_matching_orgs(self, org_name):
        """ Either update an exisiting record or create a new record and commit to the database """
        org_list = self.extract_record(org_name)
        row = None
        if (len(org_list) == 0):
            # No existing record found, create a placeholder"
            values = ['None'] * len(PasswordManager._SCHEMA)
            row = dict((zip(PasswordManager._SCHEMA, values)))
            row['ORGANIZATION'] = org_name
            row['DATE'] = datetime.date.today().isoformat()
            org_list.append(len(self._password_table))
            self._password_table.append(row)

        for index in org_list:
            self._ask_user_and_update_record(index)

    def print_record(self, index):
        """ Present the record to the user """
        print(f"INDEX[{index}]")
        row = self._password_table[index]
        self._pretty.pprint(row)

    def backup(self):
        """ Backup the database to a date indexed backup copy """
        new_csv_file_name = self._get_backup_csv_file_name()
        os.makedirs(PasswordManager._BACKUPDIR, exist_ok = True)
        shutil.copyfile(self._csv_file_name, new_csv_file_name)
        print(f"Backed up the database to CSV file {new_csv_file_name}")

def parse_command_line(args):
    """ Command line parsing helper routine """
    msg = "Lookup (and or update) the password for the organization requested"
    parser = argparse.ArgumentParser(description = msg, exit_on_error = False)
    parser.add_argument('-o', '--org', dest = 'oname', nargs = 1, required=True)
    parser.add_argument('-u', '--update', dest = 'update', action='store_true')
    parser.add_argument('-r', '--root', dest ='rname', nargs = 1)
    # strip out the argv[0]
    return parser.parse_args(args[1:])

def main(args):
    """ Main entry point """
    try:
        argtab = parse_command_line(args)
        pman = None
        if (argtab.rname):
            pman = PasswordManager(argtab.rname[0])
        else:
            pman = PasswordManager()
        indexes = pman.extract_record(argtab.oname[0])
        for index in indexes:
            pman.print_record(index)

        if (argtab.update):
            pman.backup()
            pman.update_matching_orgs(argtab.oname[0])
            pman.write_updated_table()
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
