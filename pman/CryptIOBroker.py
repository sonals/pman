# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 sonal.santan@gmail.com
#

import base64
import cryptography.fernet
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.kdf.pbkdf2
import getpass
import io
import json
import os
import pprint
import tempfile
import secrets


import csv

class CryptIOBroker(io.StringIO):
    """
    A simple wrapper around io.StringIO module. Provides transparent encryption of
    all writes and inline decryption of all reads. The encrypted data is stored or
    retrieved from the file provided.
    The password provided in the class constructor is stretched and then paired with
    a salt following the Python cryptography example described here--
    https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/code
    The module stages all data in the backing storage of base class, io.StringIO.
    1. Base class methods write() and writelines() store the unencrypted contents into the
       backing storage provided by the base class. The overridden close() method is used
       to encrypt the stored data and then flush it to the file.
    2. Base class methods read()/readlines() retieve decrypted contents from the backing
       storage provided by the base class. The backing storage is fully populated by reading
       all data from the file and decrypting it in the module constructor.
    """

    _SELFTESTFILE = "/tmp/ducati-store.dat"

    @classmethod
    def _getengine(cls, password, salt):
        kdf = cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC(
            algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000)

        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
        return cryptography.fernet.Fernet(key)

    def __init__(self, password, mode, filename):
        """ CryptIOBroker class constructor """
        self._mode = mode
        self._dbfilename = filename
        # Only exclusive read or write operation is supported; 'rw' is not supported
        if (self._mode not in ('r', 'w')):
            raise (RuntimeError("Only read text or write test mode is supported; mixed read-write mode is not supported"))

        if (self._mode == 'r'):
            with open(self._dbfilename, mode='rb') as filehandle:
                self._salt = filehandle.read(16)
                self._engine = CryptIOBroker._getengine(password, self._salt)
                bindata = filehandle.read()
                contents = self._engine.decrypt(bindata)
            super().__init__(contents.decode('utf-8'))
        else:
            self._salt = os.urandom(16)
            self._engine = CryptIOBroker._getengine(password, self._salt)
            super().__init__()

    def close(self):
        if (self._mode == 'w'):
            contents = super().getvalue()
            with open(self._dbfilename, mode='wb') as filehandle:
                bindata = self._engine.encrypt(contents.encode('utf-8'))
                filehandle.write(self._salt)
                filehandle.write(bindata)
        super().close()

    @classmethod
    def selftest(cls):
        tfile = tempfile.NamedTemporaryFile(delete=False)
        tfile.close()
        tname = tfile.name

        pretty = pprint.PrettyPrinter(indent=4, sort_dicts=False)

        password = secrets.token_hex(8)

        wbroker = CryptIOBroker(password, 'w', tname)
        wlines = ["hello\n", "bye\n"]
        wbroker.writelines(wlines)
        wbroker.close()

        rbroker = CryptIOBroker(password, 'r', tname)
        rlines = rbroker.readlines()
        pretty.pprint(rlines)
        rbroker.close()
        os.unlink(tname)

        assert (wlines == rlines), f"{cls} built-in selftest failed"


_SCHEMA = ['ORGANIZATION', 'URL', 'USERID', 'PASSWD', 'OTHERID1', 'OTHERID2', 'DATE',
           'KIND', 'NOTES']
def etest():
    key = cryptography.fernet.Fernet.generate_key()
    f = cryptography.fernet.Fernet(key)
    edata = f.encrypt(b"A really secret message. Not for prying eyes.")
    ddata = f.decrypt(edata)
    print(ddata)

def keytest():
    password = b"password"
    salt = os.urandom(16)
    kdf = cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC(
        algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000)

    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = cryptography.fernet.Fernet(key)

    data = None
    with open("/tmp/password.csv", mode='r', encoding='utf8') as csv_file_handle:
        data = csv_file_handle.read()

    reader = csv.DictReader(io.StringIO(data), delimiter=',', quoting=csv.QUOTE_MINIMAL)
    assert(reader.fieldnames == _SCHEMA)
    pretty = pprint.PrettyPrinter(indent=4, sort_dicts=False)
    for row in reader:
        pretty.pprint(row)

    token = f.encrypt(b"Secret message!")
    data = f.decrypt(token)


    output = io.StringIO()

def brokertest():
    CryptIOBroker.selftest()

if __name__ == '__main__':
    brokertest()
    keytest()
