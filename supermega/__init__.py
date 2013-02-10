from __future__ import absolute_import

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.strxor import strxor
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util import Counter
from Crypto.Random import random

from .utils import b64encode, b64decode

import itertools
import weakref
import datetime
import json
import urlparse
import os
import os.path
import requests
import logging

from . import errors
from . import protocol
from . import transport
from . import models
from . import utils
from . import errors
from . import protocol

__all__ = [ 'Session', 'File', 'User' ]

class Session(object):
    def __init__(self, username = None, password = None):
        self.sequence = itertools.count(0)
        self.keystore = models.Keystore()
        self.datastore = models.Datastore()

        # self._poller = gevent.Greenlet(self._poll_server)

        self._reqs_session = requests.Session()
        self._reqs_session.stream = True
        self._reqs_session.params['ssl'] = 1

        if username:
            self.login(username, password)

    def _maxaction():
        doc = "The _maxaction property."
        def fget(self):
            return self.__maxaction
        def fset(self, value):
            self.__maxaction = value
            #if value and not bool(self._poller):
            #   self._poller.start()
            #elif not value and bool(self._poller):
            #   self._poller.kill(block=False)
        def fdel(self):
            del self.__maxaction
            #self._poller.kill(block=False)

        return locals()
    _maxaction = property(**_maxaction())

    @property
    def root(self):
        if self.datastore.root is None:
            self.init_datastore()
        return self.datastore.root

    @property
    def trash(self):
        if self.datastore.trash is None:
            self.init_datastore()
        return self.datastore.trash

    @property
    def inbox(self):
        if self.datastore.inbox is None:
            self.init_datastore()
        return self.datastore.inbox

    def __str__(self):
        if not self.user:
            return self.__repr__()

        return "%s for user '%s'" % (self.__name__, self.user.username)

    def login(self, username, password):
        self.user = User(self)
        self.user.login(username, password)

    def ephemeral(self):
        self.user = User(self)
        self.user.ephemeral()

    def init_datastore(self):
        req = protocol.FilesRequest()
        res = req.send(self)

        self._maxaction = res['maxaction']
        for data in res['files']:
            meta = models.Meta.for_data(data, self)
            self.datastore.add(meta)

    def download(self, func, file, *args, **kwargs):
        if isinstance(file, basestring):
            (handle, cipher_info) = models.File.parse_download_url(file)

            req = protocol.PublicFileDownloadRequest(handle)
            res = req.send(self)

            file = models.File.deserialize(res.as_dict(), handle=handle,
                session=self, cipher_info=cipher_info)

            req = self._reqs_session.get(res['url'], stream=True,
                params={'sid': None, 'ssl': None})

            func(file, file.decrypt_from_stream(req.raw), *args, **kwargs)
        else:
            file.download(func, *args, **kwargs)

    def download_to_file(self, file, handle = None):
        self.download(self._to_file, file, handle)

    @staticmethod
    def _to_file(file, chunks, handle):
        if not handle:
            with open(file.name, 'wb') as handle:
                for chunk in chunks:
                    handle.write(chunk)
        else:
            for chunk in chunks:
                handle.write(chunk)

    @utils.retry(protocol.RETRY_CONDITIONS)
    def _poll_server(self):
        while True:
            # If we're running, _maxaction is guaranteed to be set
            req = transport.ServerRequest(self._maxaction, self)
            content = req.send().content

            res = protocol.ServerResponse()
            res.load(req, content)

            if 'wait_url' in res:
                self._reqs_session.get(res['wait_url'], params = {'ssl': None, 'sid': None})
            else:
                # TODO: Handle opcode
                print "opcode = {}, maxaction = {}".format(res['opcode'], res['maxaction'])
                self._maxaction = res['maxaction']

class User(object):
    AES_KEY_LENGTH_BITS = 128

    def __init__(self, session):
        self._session = session

    def login(self, username, password):
        self.username = username
        self.password = password
        self._derived = User.derive_key(password)

        req = protocol.UserSessionRequest(username, self.userhash)
        res = req.send(self._session)

        self._decrypt_master_key(res['master_key'])
        self._decrypt_private_key(res['private_key'])
        self._decrypt_csid(res['session_id'])

        # This effectively completes the login, sid will be appended to all
        # requests going forward.
        self._session._reqs_session.params['sid'] = self.session_id

        self.update()

    def ephemeral(self):
        self._derived = long_to_bytes(
            random.getrandbits(self.AES_KEY_LENGTH_BITS))
        self.master_key = long_to_bytes(
            random.getrandbits(self.AES_KEY_LENGTH_BITS))
        challenge = long_to_bytes(random.getrandbits(self.AES_KEY_LENGTH_BITS))

        cipher = AES.new(self._derived, mode=AES.MODE_CBC, IV='\0'*16)
        cipher_master = AES.new(self.master_key, mode=AES.MODE_CBC, IV='\0'*16)

        req = protocol.UserUpdateRequest(
            b64encode(utils.encrypt(cipher, self.master_key)),
            b64encode(challenge + utils.encrypt(cipher_master, challenge))
        )
        res = req.send(self._session)

        print res.as_dict()

        req = protocol.EphemeralUserSessionRequest(res['handle'])
        res = req.send(self._session)

        self._decrypt_master_key(res['master_key'])
        self._decrypt_tsid(res['session_id'])

        self._session._reqs_session.params['sid'] = self.session_id

    def update(self):
        req = protocol.UserInformationRequest()
        res = req.send(self._session)

        public_key = res['public_key']
        userhandle = res['userhandle']

        self.userhandle = userhandle
        self._session.keystore[userhandle] = self.master_key

        public_key = b64decode(public_key)

        n, offset = utils.mpi_to_bytes(public_key)
        e, _      = utils.mpi_to_bytes(public_key, offset)

        n, e = map(bytes_to_long, (n, e))

        pk = self.private_key
        self.rsa = RSA.construct((n, e, pk.d, pk.p, pk.q, pk.u))
        del self.private_key

    def _decrypt_master_key(self, c):
        cipher = AES.new(self._derived, mode=AES.MODE_ECB)
        self.master_key = utils.decrypt(cipher, b64decode(c))

    def _decrypt_private_key(self, c):
        assert(self.master_key != '')

        cipher = AES.new(self.master_key, mode=AES.MODE_ECB)
        c = utils.decrypt(cipher, b64decode(c))
        
        p, offset = utils.mpi_to_bytes(c)
        q, offset = utils.mpi_to_bytes(c, offset)
        d, offset = utils.mpi_to_bytes(c, offset)
        u, _      = utils.mpi_to_bytes(c, offset)

        self.private_key = utils.RSAPartialKey(*map(bytes_to_long, (p, q, d, u)))

    def _decrypt_csid(self, c):
        c, _ = utils.mpi_to_bytes(b64decode(c))
        c = utils.rsa_decrypt_with_partial(c, self.private_key)

        # Take only first 43 bytes since the sid is 0 padded
        self.session_id = b64encode(long_to_bytes(c)[:43])

    def _decrypt_tsid(self, c):
        c_binary = b64decode(c)
        cipher = AES.new(self.master_key, mode=AES.MODE_CBC, IV='\0'*16)

        if not utils.encrypt(cipher, c_binary[:16]) == c_binary[-16:]:
            raise errors.SupermegaException('Temporary session id is invalid')

        self.session_id = c

    def hash(self, string):
        return User.hash_with_key(string, self._derived)

    @property
    def userhash(self):
        return self.hash(self.username)

    @staticmethod
    def derive_key(string):
        key = '\x93\xC4\x67\xE3\x7D\xB0\xC7\xA4\xD1\xBE\x3F\x81\x01\x52\xCB\x56'

        for r in xrange(65536):
            for chunk in utils.chunks(string, AES.block_size):
                chunk += '\x00' * (AES.block_size - len(chunk))
                cipher = AES.new(chunk, mode = AES.MODE_ECB)

                key = cipher.encrypt(key)

        return key

    @staticmethod
    def hash_with_key(string, key):
        hash = '\x00' * AES.block_size
        cipher = AES.new(key, mode = AES.MODE_ECB)

        for chunk in utils.chunks(string, AES.block_size):
            chunk += '\x00' * (AES.block_size - len(chunk))
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
        if hasattr(meta, 'parent') and meta.parent:
            parent = self._objects[meta.parent]
            parent.children.add(meta)
        elif hasattr(meta, 'type'):
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

    def __init__(self, session):
        self._session = session

    @classmethod
    def deserialize(cls, data, **kwargs):
        obj = cls(kwargs.pop('session'))
        obj._deserialize(data, kwargs)
        return obj

    def _deserialize(self, data, kwargs):
        self.handle = data.get('handle', None) or kwargs['handle']
        # TODO: Make this required?
        self.created = ('timestamp' in data and
            datetime.datetime.fromtimestamp(data['timestamp']) or None)
        # TODO: Refactor and make this required?
        self.owner = data.get('owner', None)

    @classmethod
    def for_data(cls, data, session):
        try:
            meta_class = cls.TYPES[data['type']]
        except KeyError:
            raise errors.SupermegaException(
                'Invalid object / file type: {}'.format(data['type']))

        return meta_class.deserialize(data, session=session)

meta_data_for = utils.registry(Meta, 'TYPES')

@meta_data_for(Meta.TYPE_ROOT, Meta.TYPE_INBOX, Meta.TYPE_TRASH)
class Container(Meta):
    """Represents an object that can store other objects as children of
    itself. In the MEGA storage model these are the special nodes (root, trash,
    etc.) as well as directories."""

    def _deserialize(self, data, kwargs):
        super(Container, self)._deserialize(data, kwargs)
        self.children = weakref.WeakSet()
        self.type = data['type']

    def __iter__(self):
        return iter(self.children)

    def __str__(self):
        return '<{}.{} object with handle {}>'.format(
            self.__class__.__module__, self.__class__.__name__, self.handle)

    def __repr__(self):
        return self.__str__()

    @property
    def subdirs(self):
        return itertools.ifilter(self.is_container, self.children)

    @property
    def files(self):
        return itertools.ifilterfalse(self.is_container, self.children)

    def walk(self):
        yield (self, self.subdirs, self.files)

        for subdir in self.subdirs:
            for result in subdir.walk():
                yield result

    @staticmethod
    def is_container(obj):
        return isinstance(obj, Container)

class Containee(object):
    """Represents an object in the file tree that can be stored in a
    container, i.e. it has a parent. Currently directories and files are
    possible."""

    def _deserialize(self, data, kwargs):
        super(Containee, self)._deserialize(data, kwargs)

        # TODO: Refactor and make this required
        self.parent = data.get('parent', None)

        keystore = self._session.keystore
        cipher_info = kwargs.get('cipher_info', None)

        if not cipher_info:
            ## Find a suitable user / share key to decrypt the object key
            self.keys = dict([x.split(':') for x in data['keys'].split('/')])
            key_id, intermediate_key = keystore.get_any(self.keys.iterkeys())

            if not key_id:
                raise SupermegaException("Missing a shared key")

            ## Decrypt file key
            cipher = AES.new(intermediate_key, mode=AES.MODE_ECB)
            cipher_info = utils.decrypt(cipher, b64decode(self.keys[key_id]))

        self._extract_cipher_spec(cipher_info)
        assert(self.key is not None)

        ## Decrypt attributes (name as of now)
        cipher = AES.new(self.key, mode=AES.MODE_CBC, IV='\0'*AES.block_size)
        attrs = utils.decrypt(cipher, b64decode(data['attrs'])).strip('\0')

        if not attrs.startswith('MEGA'):
            print 'File attributes are not in a valid format (file "{}")'.format(self.handle)
        else:
            self.raw_attrs = attrs # TODO: Remove me
            attrs = json.loads(attrs[4:])
            self.name = attrs['n']

    def get_encrypted_attrs(self):
        attrs = 'MEGA' + json.dumps({'n': self.name})
        cipher = AES.new(self.key, mode=AES.MODE_CBC, IV='\0'*AES.block_size)
        return b64encode(utils.encrypt(cipher, attrs))

    def get_serialized_key(self):
        raise NotImplementedError

    def _extract_cipher_spec(self, cipher_info):
        raise NotImplementedError

    def __str__(self):
        return '<{} "{}" ({})>'.format(
            self.__class__.__name__, self.name, self.handle)

    __repr__ = __str__

@meta_data_for(Meta.TYPE_DIRECTORY)
class Directory(Containee, Container):
    @classmethod
    def create(cls, name, parent):
        pass

    def get_serialized_key(self):
        return self.key

    def _extract_cipher_spec(self, cipher_info):
        assert(len(cipher_info) == 16)
        self.key = cipher_info

@meta_data_for(Meta.TYPE_FILE)
class File(Containee, Meta):
    type = Meta.TYPE_FILE

    def _deserialize(self, data, kwargs):
        super(File, self)._deserialize(data, kwargs)
        self.size = data['size']

    @classmethod
    def from_stream(cls, name, stream, size = None):
        obj = cls()
        obj.name = name

        if not size:
            size = os.fstat(stream).st_size

        obj.size = size
        obj._stream = stream

    @classmethod
    def from_disk(cls, path):
        filename = os.path.basename(path)
        with open(path, 'rb') as stream:
            return cls.from_stream(name, stream)

    @classmethod
    def upload(cls, parent, source, name = None, size = None):
        chunks = None

        if isinstance(source, File):
            name = name or source.name
            size = source.size
            chunks = source.chunks()
        else:
            # Assume that source is a file-like object
            size = size or os.fstat(source.fileno()).st_size
            chunks = utils.chunk_stream(source, cls.chunk_lengths())

        assert(name is not "")

        req = protocol.FileUploadRequest(size)
        base_url = req.send(parent._session)['url'] + '/{}'
        requests_session = parent._session._reqs_session

        key = key or long_to_bytes(random.getrandbits(128))
        iv = iv or long_to_bytes(random.getrandbits(64))

        counter = Counter.new(64, prefix=iv, initial_value=0)
        cipher = AES.new(key, mode=AES.MODE_CTR, counter=counter)

        # TODO: Handle corrupt file source

        file_mac = '\0' * AES.block_size
        completion_token = ""
        bytes_read = 0

        for chunk in chunks:
            chunk_mac = cls.calculate_chunk_mac(key, iv, chunk)
            chunk = utils.encrypt(cipher, chunk)

            mac_cipher = AES.new(key, mode=AES.MODE_CBC,
                IV='\0'*AES.block_size)
            file_mac = strxor(file_mac, chunk_mac)
            file_mac = utils.encrypt(mac_cipher, file_mac)

            url = base_url.format(bytes_read)
            res = requests_session.post(url, data=chunk,
                params={'sid': None, 'ssl': None})

            bytes_read += len(chunk)

            if res.content == "":
                # This chunk upload was sucessful
                continue

            try:
                raise errors.ServiceError.for_errno(int(res.content))
            except ValueError:
                # This is the last chunk
                completion_token = res.content

        if completion_token:
            # Finalize MAC
            file_mac = (strxor(file_mac[:4], file_mac[4:8]) +
                        strxor(file_mac[8:12], file_mac[12:]))

            print "completion token is " + completion_token
            new_file = cls(parent._session)
            new_file.name = name
            new_file.size = size
            new_file.iv = iv
            new_file.mac = file_mac
            new_file.key = key

            req = protocol.FileAddRequest(parent, new_file, completion_token)
            res = req.send(parent._session)

            assert(len(res['files']) == 1)

            for data in res['files']:
                # TODO Make this work for multiple files?
                f = Meta.for_data(data, parent._session)
                parent._session.datastore.add(f)
                return f

    def chunks(self):
        req = protocol.FileDownloadRequest(self)
        res = req.send(self._session)

        req = self._session._reqs_session.get(res['url'], stream=True,
            params={'sid': None, 'ssl': None})
        return self.decrypt_from_stream(req.raw)

    def download(self, func, *args, **kwargs):
        func(self, self.chunks(), *args, **kwargs)

    def move_to(self, new_parent):
        if not isinstance(new_parent, Container):
            raise TypeError('The new parent has to be a container')

        req = protocol.FileMoveRequest(self, new_parent)
        res = req.send(self._session)
        assert(res['errno'] == 0)

    def delete(self):
        req = protocol.FileDeleteRequest(self)
        res = req.send(self._session)
        assert(res['errno'] == 0)

    def _extract_cipher_spec(self, cipher_info):
        # 128bit key XORed with trailing 128bit,
        # followed by upper 64bit of CTR mode IV,
        # again followed by 64bit MAC
        # Thanks http://julien-marchand.fr/blog/using-mega-api-with-python-examples/
        self.key = strxor(cipher_info[0:16], cipher_info[16:32])
        self.iv = cipher_info[16:24]
        self.mac = cipher_info[24:]

    def decrypt_from_stream(self, stream):
        # Prefix (IV) is 64 bits, so we get a 128bit counter, just what the
        # doctor ordered.
        # Caveat: this might overflow differently than the MEGA implementation.
        counter = Counter.new(64, prefix=self.iv, initial_value=0)
        cipher = AES.new(self.key, mode=AES.MODE_CTR, counter=counter)

        bytes_read = 0
        file_mac = '\0' * 16

        for chunk in utils.chunk_stream(stream, self.chunk_lengths()):
            bytes_read += len(chunk)

            chunk = utils.decrypt(cipher, chunk)
            chunk_mac = self.calculate_chunk_mac(self.key, self.iv, chunk)

            # See above
            mac_cipher = AES.new(self.key, mode=AES.MODE_CBC, IV='\0'*16)
            file_mac = strxor(file_mac, chunk_mac)
            file_mac = utils.encrypt(mac_cipher, file_mac)

            yield chunk

        if bytes_read != self.size:
            raise errors.CorruptFile(
                "Corrupt download: file is too short")
                
        file_mac = (strxor(file_mac[:4], file_mac[4:8]) +
            strxor(file_mac[8:12], file_mac[12:]))

        # TODO: Should we use a constant time compare?
        if file_mac != self.mac:
            raise errors.CorruptFile(
                "Corrupt download: invalid hash")

    def get_serialized_key(self):
        cipher = AES.new(self._session.user.master_key, mode=AES.MODE_ECB)
        key = strxor(self.key, self.iv + self.mac)
        ciphertext = utils.encrypt(cipher, key + self.iv + self.mac)
        assert(len(ciphertext) == 32)
        return b64encode(ciphertext)

    @staticmethod
    def calculate_chunk_mac(key, iv, chunk):
        chunk_mac = iv * 2
        for block in utils.chunks(chunk, AES.block_size):
            # TODO: Isn't this really ECB?
            # TODO: This might require padding
            mac_cipher = AES.new(key, mode=AES.MODE_CBC, IV='\0'*16)

            chunk_mac = strxor(chunk_mac, block.ljust(AES.block_size, '\0'))
            chunk_mac = utils.encrypt(mac_cipher, chunk_mac)

        return chunk_mac

    @staticmethod
    def parse_download_url(url):
        info = urlparse.urlparse(url).fragment.lstrip('!').split('!', 2)
        return info[0], b64decode(info[1])

    @staticmethod
    def chunk_lengths():
        # First 8 chunks are 128 kbyte, the rest 1024 kbyte
        return itertools.chain([0x20000 * (i+1) for i in xrange(8)],
            itertools.repeat(0x100000))
    