#!/usr/bin/env python3
#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 sonal.santan@gmail.com
#

"""
This is a simple command line based password manager which stores users password in
an ecrypted database. The database is organized as a CSV file with the schema defined
by _SCHEMA. The DB is encrypted using user's password and a random salt. The salt is
regenerated for every database update.

"""

import argparse
import csv
import datetime
import getpass
import os
import pprint
import re
import shutil
import sys
import urllib.parse

import cryptography.fernet

import CryptIOBroker

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
    _PASSDB = 'password.db'
    _BACKUPDIR = 'backup.d'

    def load_database(self):
        """ Initialize the in memory database by reading from database file """
        broker = CryptIOBroker.CryptIOBroker(self._password, 'r', self._db_file_name)
        reader = csv.DictReader(broker, delimiter=',', quoting=csv.QUOTE_MINIMAL)
        assert(reader.fieldnames == PasswordManager._SCHEMA)
        for row in reader:
            self._password_table.append(row)
        broker.close()

    def __init__(self, password, root_dir = PRIVATEDIR):
        """ PasswordManager class constructor """
        self._password = password
        self._db_file_name = f'{root_dir}/{PasswordManager._PASSDB}'
        self._pretty = pprint.PrettyPrinter(indent=4, sort_dicts=False)
        print(f"Using database file {self._db_file_name}...")
        self._password_table = []
        self._dirty = False
        self._backup_dir = os.path.dirname(self._db_file_name)
        self._backup_dir += f'/{PasswordManager._BACKUPDIR}'

        try:
            self.load_database()
        except(FileNotFoundError) as ferr:
            print(f"Database {self._db_file_name} not found, creating empty database...")
            self.write_updated_table()
        except(cryptography.fernet.InvalidToken ) as ierr:
            print(f"Invalid password for database {self._db_file_name}, exiting")
            raise(ierr)
        except Exception as eerr:
            raise(eerr)
        print(f"Total {len(self._password_table)} records found")

    def _get_backup_csv_file_name(self):
        """ Generate date indexed CSV file name to backup the database """
        base_ext = os.path.splitext(PasswordManager._PASSDB)
        csv_backup_file_name = self._backup_dir
        csv_backup_file_name += f'/{base_ext[0]}'
        csv_backup_file_name += '.'
        csv_backup_file_name += datetime.date.today().isoformat()
        csv_backup_file_name += f'{base_ext[1]}'
        return csv_backup_file_name

    def write_updated_table(self):
        """ Write out the updated database to the CSV file """
        broker = CryptIOBroker.CryptIOBroker(self._password, 'w', self._db_file_name)
        writer = csv.DictWriter(broker, PasswordManager._SCHEMA,
                                restval = None, delimiter=',', quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for row in self._password_table:
            writer.writerow(row)
        print(f"Committed {len(self._password_table)} records to the CSV file {self._db_file_name}")
        broker.close()

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
                    self._dirty = True

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
        os.makedirs(self._backup_dir, exist_ok = True)
        shutil.copyfile(self._db_file_name, new_csv_file_name)
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
        CryptIOBroker.CryptIOBroker.selftest()
        argtab = parse_command_line(args)
        pman = None
        value = getpass.getpass("Password: ")
        if (argtab.rname):
            pman = PasswordManager(value, argtab.rname[0])
        else:
            pman = PasswordManager(value)
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
