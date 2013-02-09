import base64
import struct
from itertools import izip
from cStringIO import StringIO
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long
from collections import namedtuple

B64_ALT_CHARS = '-_'

def b64encode(s):
    return base64.b64encode(s, B64_ALT_CHARS).rstrip('=')

def b64decode(s):
    if isinstance(s, unicode):
        s = s.encode('ascii')

    padding = '=' * (4 - (len(s) % 4))
    return base64.b64decode(s + padding, B64_ALT_CHARS)

def chunks(s, n):
    for i in xrange(0, len(s), n):
        yield s[i:i+n]

def decrypt(cipher, ciphertext, block_size=16):
    buf = StringIO()
    for chunk in chunks(ciphertext, block_size):
        length = len(chunk)
        if length < block_size:
            chunk = cipher.decrypt(chunk.ljust(block_size, '\0'))[:length]
        else:
            chunk = cipher.decrypt(chunk)
        buf.write(chunk)
    return buf.getvalue()

def encrypt(cipher, plaintext, block_size=16):
    buf = StringIO()
    for chunk in chunks(plaintext, block_size):
        buf.write(cipher.encrypt(chunk.ljust(block_size, '\0')))
    return buf.getvalue()

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
