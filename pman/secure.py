# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 sonal.santan@gmail.com
#

import base64
import cryptography.fernet
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.kdf.pbkdf2
import io
import os
import pprint
import csv

class CryptIOBroker(io.StringIO):
    """
    A simple wrapper around io.StringIO moduel. Provides inline encryption of all writes
    and inline decryption of all reads. The password provided in the class constructor
    is stretched and then used with Fernet to encrypt (for writes) or decrypt (for reads)
    the contents. The encrypted contents are ultimately stored (for writes) or preemptively
    retreived (for reads) to/from the file provided by the user.
    1. Base class methods write() and writelines() store the passed contents into the
       backing storage provided by the base class. The overridden close() method is used
       to encrypt the stored data and flush it to the file.
    2. Base class methods read()/readlines() retieve contents from the storage provided
       by the base class. The data is fully read from the file and decrypted in one go
       in the constructor.
    """
    def __init__(self, password, mode, filename):
        """ CryptIOBroker class constructor """
        self._mode = mode
        self._filename = filename
        self._salt = b'abcdabcdabcdabcd'
        self._kdf = cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC(
            algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=480000)

        key = base64.urlsafe_b64encode(self._kdf.derive(password.encode('utf-8')))
        self._engine = cryptography.fernet.Fernet(key)
        assert((self._mode == 'r') or (self._mode == 'w'))

        if (self._mode == 'r'):
            contents = None
            with open(self._filename, mode='rb') as filehandle:
                bindata = filehandle.read()
                contents = self._engine.decrypt(bindata)
            super().__init__(contents.decode('utf-8'))
        else:
            super().__init__()

    def close(self):
        if (self._mode == 'w'):
            contents = super().getvalue()
            with open(self._filename, mode='wb') as filehandle:
                bindata = self._engine.encrypt(contents.encode('utf-8'))
                filehandle.write(bindata)
        super().close()


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
    c = CryptIOBroker("sonals", 'w', "/tmp/ducati.dat")
    c.writelines("hello\n")
    c.writelines("bye\n")
    c.close()

    d = CryptIOBroker("sonals", 'r', "/tmp/ducati.dat")
    r = d.readlines()
    pretty = pprint.PrettyPrinter(indent=4, sort_dicts=False)
    pretty.pprint(r)
    d.close()

if __name__ == '__main__':
    brokertest()
    keytest()
