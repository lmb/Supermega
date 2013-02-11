import base64
import struct
from itertools import izip
from cStringIO import StringIO
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long
from Crypto.Util.strxor import strxor
from collections import namedtuple

B64_ALT_CHARS = '-_'

def b64encode(s):
    return base64.b64encode(s, B64_ALT_CHARS).rstrip('=')

def b64decode(s):
    if isinstance(s, unicode):
        s = s.encode('ascii')

    padding = '=' * (4 - (len(s) % 4))
    return base64.b64decode(s + padding, B64_ALT_CHARS)

def chunks(s, n, padding = 0):
    for i in xrange(0, len(s), n):
        yield s[i:i+n].ljust(padding, '\0')

def chunk_stream(stream, chunk_lengths):
    for length in chunk_lengths:
        chunk = stream.read(length)

        if not chunk:
            break

        yield chunk

def decrypt(cipher, ciphertext):
    length = len(ciphertext)

    if cipher.mode is not AES.MODE_CTR and length % cipher.block_size != 0:
        block_size = cipher.block_size
        ciphertext = ciphertext + ('\0' * (block_size - (length % block_size)))

    return cipher.decrypt(ciphertext)[:length]

def encrypt(cipher, plaintext):
    length = len(plaintext)

    if cipher.mode is not AES.MODE_CTR and length % cipher.block_size != 0:
        block_size = cipher.block_size
        plaintext = plaintext + ('\0' * (block_size - (length % block_size)))

    # Encrypted attributes keep 0 padding
    return cipher.encrypt(plaintext)

def link_unwrap(notify, args, kwargs):
    """Unwraps the result of a greenlet execution and passes it to notify()."""
    def unwrapper(greenlet):
        notify(greenlet.value, *args, **kwargs)

    return unwrapper

RSAPartialKey = namedtuple('RSAPartialKey', ['p', 'q', 'd', 'u'])

# From http://stackoverflow.com/questions/10689273/
def rsa_decrypt_with_partial(c, key):
    """Decrypts a given ciphertext with modulus and private exponent only.

    The ciphertext must not be longer than the modulo."""
    n = key.p * key.q

    try:
        # pycrypto >=2.5, only tested with _slowmath
        impl = RSA.RSAImplementation(use_fast_math=False)
        partial = impl.construct((n, 0L))
        partial.key.d = key.d
    except TypeError:
        # pycrypto <=2.4.1
        partial = RSA.construct((n, 0L, key.d)) 

    # TODO: Fix assert
    # assert(len(c) <= len(n))

    c = bytes_to_long(c)
    return partial.key._decrypt(c)

def cbc_mac(key, plaintext, IV = None):
    IV = IV or '\0' * AES.block_size

    cipher = AES.new(key, AES.MODE_CBC, IV=IV)
    for block in chunks(plaintext, AES.block_size, AES.block_size):
        mac = cipher.encrypt(block)

    return mac

# As per http://stackoverflow.com/questions/1857780/sparse-assignment-list-in-python
class SparseList(list):
  def __setitem__(self, index, value):
    missing = index - len(self) + 1
    if missing > 0:
      self.extend([None] * missing)
    list.__setitem__(self, index, value)
  def __getitem__(self, index):
    try: return list.__getitem__(self, index)
    except IndexError: return None

class MetaMAC(object):
    def __init__(self, key, iv):
        self.key = key
        # IV is used for CTR mode en/decrypion and is only 64 bits as a result
        # MEGA just takes it twice for CBC-MAC operation
        self.iv = iv * 2
        self.macs = SparseList()

    def update(self, chunk_index, chunk):
        if self.macs[chunk_index] is not None:
            raise KeyError('Chunk MACs should not be set multiple times')
        self.macs[chunk_index] = cbc_mac(self.key, chunk, IV=self.iv)

    def digest(self):
        try:
            mac = cbc_mac(self.key, ''.join(self.macs)) # Zero IV
        except TypeError:
            raise ValueError('Not all chunk MACs have been submitted')

        return strxor(mac[:4], mac[4:8]) + strxor(mac[8:12], mac[12:])

def registry(registry_class, attr):
    if not hasattr(registry_class, attr):
        setattr(registry_class, attr, {})

    def wrap_helper(*values):
        def wrap_class(registered_class):
            attr_instance = getattr(registry_class, attr)
            for value in values:
                if value in getattr(registry_class, attr):
                    raise Exception("Re-registering: {}".format(value))
                    
                attr_instance[value] = registered_class
            return registered_class
        return wrap_class
    return wrap_helper

def mpi_to_bytes(mpi, offset = 0):
    """Converts a RFC2880 (?) multi-precision integer into a corresponding byte array.

    MPIs are prefixed with a big endian uint16 that gives their length in _bits_."""

    if len(mpi) - offset < 2:
        # TODO: Find a better exception
        raise Exception("mpi is less than two bytes long")

    bits, = struct.unpack('>H', mpi[offset:offset + 2]);
    bytes = (bits + 7) // 8;
    offset += 2

    if len(mpi) < offset + bytes:
        raise Exception("Not enough data left")

    return mpi[offset:offset + bytes], offset + bytes


# Adapted from http://www.saltycrane.com/blog/2009/11/trying-out-retry-decorator-python/
import time
from functools import wraps

def retry(ExceptionToCheck, tries=3, delay=5, backoff=2, logger=None):
    """Retry calling the decorated function using an exponential backoff.

    :param ExceptionToCheck: the exception to check. may be a tuple of
        exceptions to check
    :type ExceptionToCheck: Exception or tuple
    :param tries: number of times to try (not retry) before giving up
    :type tries: int
    :param delay: initial delay between retries in seconds
    :type delay: int
    :param backoff: backoff multiplier e.g. value of 2 will double the delay
        each retry
    :type backoff: int
    :param logger: logger to use. If None, print
    :type logger: logging.Logger instance
    """
    def deco_retry(f):
        @wraps(f)
        def retry_decorator(*args, **kwargs):
            mtries, mdelay = tries, delay
            while mtries > 1:
                try:
                    return f(*args, **kwargs)
                except ExceptionToCheck, e:
                    msg = "%s, retrying in %d seconds..." % (str(e), mdelay)
                    if logger:
                        logger.warning(msg)
                    else:
                        print msg
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
            return f(*args, **kwargs)

        return retry_decorator  # true decorator
    return deco_retry
