from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.strxor import strxor
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util import Counter
from Crypto import Random

from .utils import chunks, b64encode, b64decode, decrypt, mpi_to_bytes, rsa_decrypt_with_partial, RSAPartialKey

import itertools
import weakref
import datetime
import json
import urlparse

from . import utils
from . import errors

class User(object):
    def __init__(self, session, username, password):
        self.username = username
        self.password = password
        self._derived = User.derive_key(password)
        self._session = session

    def decrypt_session_id(self, master_key, session_id, private_key):
        master_key      = self._decrypt_master_key(master_key, self._derived)
        private_key     = self._decrypt_private_key(private_key, master_key)
        self.session_id = self._decrypt_sid(session_id, private_key)

        self.master_key  = master_key
        self.private_key = private_key

    def update(self, public_key, userhandle):
        self.userhandle = userhandle
        self._session.keystore[userhandle] = self.master_key

        public_key = b64decode(public_key)

        n, offset = mpi_to_bytes(public_key)
        e, _      = mpi_to_bytes(public_key, offset)

        n, e = map(bytes_to_long, (n, e))

        pk = self.private_key
        self.rsa = RSA.construct((n, e, pk.d, pk.p, pk.q, pk.u))
        del self.private_key

    def _decrypt_master_key(self, c, derived_key):
        cipher = AES.new(derived_key, mode=AES.MODE_ECB)
        return decrypt(cipher, b64decode(c))

    def _decrypt_private_key(self, c, master_key):
        assert(master_key != '')

        cipher = AES.new(master_key, mode=AES.MODE_ECB)
        c = decrypt(cipher, b64decode(c))
        
        p, offset = mpi_to_bytes(c)
        q, offset = mpi_to_bytes(c, offset)
        d, offset = mpi_to_bytes(c, offset)
        u, _      = mpi_to_bytes(c, offset)

        return RSAPartialKey(*map(bytes_to_long, (p, q, d, u)))

    def _decrypt_sid(self, c, private_key):
        c, _ = mpi_to_bytes(b64decode(c))
        c = rsa_decrypt_with_partial(c, private_key)

        return b64encode(long_to_bytes(c)[:43])

    def hash(self, string):
        return User.hash_with_key(string, self._derived)

    @property
    def userhash(self):
        return self.hash(self.username)

    @staticmethod
    def derive_key(string):
        key = '\x93\xC4\x67\xE3\x7D\xB0\xC7\xA4\xD1\xBE\x3F\x81\x01\x52\xCB\x56'

        for r in xrange(65536):
            for chunk in chunks(string, AES.block_size):
                chunk += '\x00' * (AES.block_size - len(chunk))
                cipher = AES.new(chunk, mode = AES.MODE_ECB)

                key = cipher.encrypt(key)

        return key

    @staticmethod
    def hash_with_key(string, key):
        hash = '\x00' * AES.block_size
        cipher = AES.new(key, mode = AES.MODE_ECB)

        for chunk in chunks(string, AES.block_size):
            hash = strxor(hash, chunk)

        for i in range(16384):
            hash = cipher.encrypt(hash)

        return b64encode(hash[0:4] + hash[8:12])

class Keystore(dict):
    def get_any(self, key_ids):
        for key_id in key_ids:
            if key_id in self:
                return key_id, self[key_id]

        return None, None

class Datastore(object):
    def __init__(self):
        self._objects = {}
        self.root = None
        self.inbox = None
        self.trash = None

    def add(self, meta):
        if meta.parent:
            parent = self._objects[meta.parent]
            parent.children.add(meta)
        else:
            if meta.type == Meta.TYPE_ROOT:
                self.root = meta
            elif meta.type == Meta.TYPE_INBOX:
                self.inbox = meta
            elif meta.type == Meta.TYPE_TRASH:
                self.trash = meta

        self._objects[meta.handle] = meta

    def __getitem__(self, key):
        if not len(self._objects):
            raise errors.SupermegaException("File list has not been downloaded yet")

        return self._objects[key]

class Meta(object):
    TYPE_FILE = 0
    TYPE_DIRECTORY = 1
    TYPE_ROOT = 2
    TYPE_INBOX = 3
    TYPE_TRASH = 4

    def __init__(self, keystore, data = {}):
        self._keystore = keystore

        self.handle = data.get('h', None)
        self.created = (data.has_key('ts') and
            datetime.datetime.fromtimestamp(data['ts']) or None)
        self.owner = data.get('u', None)
        # TODO: Garbage collect when parent is deleted?
        self.parent = data.get('p', None)
        self.type = data.get('t', None)

    @classmethod
    def for_data(cls, keystore, data):
        try:
            meta_class = cls.TYPES[data['t']]
        except KeyError:
            raise errors.SupermegaException('Invalid object / file type: {}'.format(data['t']))

        return meta_class(keystore, data)

meta_data_for = utils.registry(Meta, 'TYPES')

@meta_data_for(Meta.TYPE_ROOT, Meta.TYPE_INBOX, Meta.TYPE_TRASH, Meta.TYPE_DIRECTORY)
class Directory(Meta):
    def __init__(self, keystore, data):
        super(Directory, self).__init__(keystore, data)
        self.children = weakref.WeakSet()

    def __iter__(self):
        return iter(self.children)

    def __str__(self):
        return '<{}.{} object with handle {}>'.format(self.__class__.__module__, self.__class__.__name__, self.handle)

    @property
    def subdirs(self):
        return itertools.ifilter(self.is_directory, self.children)

    @property
    def files(self):
        return itertools.ifilterfalse(self.is_directory, self.children)

    def walk(self):
        yield (self, self.subdirs, self.files)

        for subdir in self.subdirs:
            for result in subdir.walk():
                yield result

    @staticmethod
    def is_directory(obj):
        return isinstance(obj, Directory)

@meta_data_for(Meta.TYPE_FILE)
class File(Meta):
    def __init__(self, keystore, data, cipher_info = None):
        super(File, self).__init__(keystore, data)

        # TODO: Make this less kludgy by mapping subobjects in requests
        self.size = data.get('s', None) or data['size']

        if not cipher_info:
            ## Find a suitable user / share key to decrypt the file key
            self.keys = dict([x.split(':') for x in data['k'].split('/')])
            key_id, intermediate_key = keystore.get_any(self.keys.iterkeys())

            if not key_id:
                raise SupermegaException("Missing a shared key")

            ## Decrypt file key
            cipher = AES.new(intermediate_key, mode=AES.MODE_ECB)
            cipher_info = decrypt(cipher, b64decode(self.keys[key_id]))

        assert(len(cipher_info) == 32)

        # 128bit key XORed with trailing 128bit,
        # followed by upper 64bit of CTR mode IV,
        # again followed by 64bit MAC
        # Thanks http://julien-marchand.fr/blog/using-mega-api-with-python-examples/
        self.key = strxor(cipher_info[0:16], cipher_info[16:])
        self.iv = cipher_info[16:24]
        self.mac = cipher_info[24:]

        ## Decrypt attributes (name as of now)
        cipher = AES.new(self.key, mode=AES.MODE_CBC, IV='\0'*16)
        attrs = decrypt(cipher, b64decode(data.get('a', None) or data['attrs'])).strip('\0')

        if not attrs.startswith('MEGA'):
            raise SupermegaException('File attributes are not in a valid format')

        attrs = json.loads(attrs[4:])
        self.name = attrs['n']

    @staticmethod
    def parse_download_url(url):
        info = urlparse.urlparse(url).fragment.lstrip('!').split('!', 2)
        return info[0], b64decode(info[1])

    def decrypt_from_stream(self, stream):
        # Prefix (IV) is 64 bits, so we get a 128bit counter, just
        # what the doctor ordered.
        # Caveat: this might overflow differently than the MEGA implementation.
        counter = Counter.new(64, prefix=self.iv, initial_value=0)
        cipher = AES.new(self.key, mode=AES.MODE_CTR, counter=counter)

        bytes_read = 0
        file_mac = '\0' * 16

        for chunk_len in self.chunk_lengths():
            chunk = stream.read(chunk_len)
            bytes_read += len(chunk)

            if not chunk:
                if bytes_read != self.size:
                    raise errors.SupermegaException("Corrupt download: file is too short")
                # TODO: Should we use a constant time compare?

                file_mac = strxor(file_mac[:4], file_mac[4:8]) + strxor(file_mac[8:12], file_mac[12:])

                if file_mac != self.mac:
                    fmac = bytes_to_long(file_mac)
                    smac = bytes_to_long(self.mac)
                    raise errors.SupermegaException("Corrupt download: invalid hash {} != {}".format(fmac, smac))

                break

            chunk = utils.decrypt(cipher, chunk)

            chunk_mac = self.iv + self.iv
            for block in utils.chunks(chunk, AES.block_size):
                # TODO: Isn't this really ECB?
                mac_cipher = AES.new(self.key, mode=AES.MODE_CBC, IV='\0'*16)

                chunk_mac = strxor(chunk_mac, block.ljust(AES.block_size, '\0'))
                chunk_mac = utils.encrypt(mac_cipher, chunk_mac)

            # See above
            mac_cipher = AES.new(self.key, mode=AES.MODE_CBC, IV='\0'*16)
            file_mac = strxor(file_mac, chunk_mac)
            file_mac = utils.encrypt(mac_cipher, file_mac)

            yield chunk


    @staticmethod
    def chunk_lengths():
        # First 8 chunks are 128 kbyte, the rest 1024 kbyte
        return itertools.chain([0x20000 * (i+1) for i in xrange(8)], itertools.repeat(0x100000))

    def __str__(self):
        return '<{}.{} "{}" [{}]>'.format(self.__class__.__module__, self.__class__.__name__, self.name, self.handle)
