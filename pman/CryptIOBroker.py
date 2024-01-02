# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 sonal.santan@gmail.com
#

import base64
import io
import os
import pprint
import secrets
import tempfile

import cryptography.fernet
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.kdf.pbkdf2

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
        """
        This is built-in loopback selftest which creates the encrypted data base saves
        it, reads it back and then validates the readback the data
        """
        pretty = pprint.PrettyPrinter(indent=4, sort_dicts=False)
        pretty.pprint(f"{cls} loopback selftest")
        tname = None
        with tempfile.NamedTemporaryFile(delete=False) as tfile:
            tname = tfile.name

        password = secrets.token_hex(8)

        wbroker = CryptIOBroker(password, 'w', tname)
        wlines = ["hello\n", "bye\n"]
        wbroker.writelines(wlines)
        wbroker.close()
        pretty.pprint(f"Wrote {wlines}")

        rbroker = CryptIOBroker(password, 'r', tname)
        rlines = rbroker.readlines()
        rbroker.close()
        os.unlink(tname)
        pretty.pprint(f"Read {rlines}")

        assert (wlines == rlines), f"{cls} built-in selftest failed"
