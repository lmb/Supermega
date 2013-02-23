import os.path
import json
import copy
import itertools
import requests.exceptions

from . import transport
from . import errors
from . import utils
from . import schemata

service_error = utils.registry(errors.ServiceError, 'ERRORS')
@service_error(-1)
class InternalError(errors.ServiceError):
    """An internal service error has occured"""
    pass

@service_error(-2)
class ArgumentError(errors.ServiceError):
    """Invalid arguments were passed to a request"""
    pass

@service_error(-3)
class RetryRequest(errors.ServiceError):
    """The server is too busy and requests a retry"""
    pass

@service_error(-5)
class UploadFailed(errors.ServiceError):
    """The upload failed"""
    pass

@service_error(-6)
class ConcurrentIPsExceeded(errors.ServiceError):
    """Too many different IPs are concurrently accessing this upload URL"""
    pass

@service_error(-7)
class InvalidRange(errors.ServiceError):
    """An invalid range header was specified"""
    pass

@service_error(-8)
class UploadURLExpired(errors.ServiceError):
    """The upload URL has expired"""
    pass

@service_error(-9)
class ObjectNotFound(errors.ServiceError):
    """Object (typically node or user) not found"""
    pass

@service_error(-10)
class CircularLinkingAttempted(errors.ServiceError):
    """A circular link was denied"""
    pass

@service_error(-11)
class AccessViolation(errors.ServiceError):
    """An access violation occured (e.g. writing to a read-only share)"""

@service_error(-12)
class ObjectExists(errors.ServiceError):
    """The object already exists on the server"""
    pass

@service_error(-13)
class ObjectIncomplete(errors.ServiceError):
    """The accessed object is incomplete"""
    pass

@service_error(-15)
class InvalidSessionId(errors.ServiceError):
    """The server indicates that the provided session id is invalid"""
    pass

@service_error(-16)
class UserBlocked(errors.ServiceError):
    """The user has been blocked"""
    pass

@service_error(-17)
class QuotaExceeded(errors.ServiceError):
    """The user quota has been exceeded"""
    pass

@service_error(-18)
class TemporarilyUnavailable(errors.ServiceError):
    """The resource is temporarily unavailable"""
    # TODO: Should this be a retry condition?
    pass

TRANSACTION_SCHEMA = schemata.Schema.from_file('transaction.json')
RETRY_CONDITIONS = (requests.exceptions.Timeout, RetryRequest,
    transport.HTTP500Error)

class Operation(object):
    _request = None
    _response = None
    _request_data = {}
    _response_data = None
    schema = None

    def __init__(self, *args, **kwargs):
        self.session = kwargs.pop('session', None)

        try:
            self._request = schemata.SchemaBundle.from_file(
                self.schema, 'request')
            self.request(*args, **kwargs)
        except KeyError:
            pass

        try:
            self._response = schemata.SchemaBundle.from_file(
                self.schema, 'response')
        except KeyError:
            pass

        if not self._request and not self._response:
            raise errors.SupermegaException(
                'Need either request or response in schema')

    def request(self, *args, **kwargs):
        pass

    def response(self, session = None):
        session = session or self.session

        if not self._response_data:
            Transaction(self).send(session)

        return copy.deepcopy(self._response_data)

    def get_serializable_request(self):
        data = self._request.translate(self._request_data)
        data[schemata.SchemaBundle.OPCODE_KEY] = self._request.opcode

        self._request.schema.validate(data)
        return data

    def load_response(self, data):
        self._response.schema.validate(data)
        self._response_data = self._response.translate(data)

    def get(self, *args, **kwargs): # ???
        return self._request_data.get(*args, **kwargs)

    def __getitem__(self, key):
        return self._request_data[key]

    def __setitem__(self, attr, value):
        self._request.validate(value, (attr,))
        self._request_data[attr] = value

    def __contains__(self, key):
        return self._request_data.__contains__(key)

class Transaction(list):
    class Encoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, Operation):
                return obj.get_serializable_request()

            return super(json.JSONEncoder, self).default(obj)

    def __init__(self, *args):
        super(Transaction, self).__init__(args)

    def serialize(self):
        return json.dumps(self, cls=self.Encoder)

    def deserialize(self, request_transaction, data):
        data = json.loads(data)

        # The server seems to return either -errno or [-errno]
        if isinstance(data, (int, long)):
            raise errors.ServiceError.for_errno(data)
        if len(data) == 1 and isinstance(data[0], (int, long)) and data[0] < 0:
            # TODO: This only catches the first error in a complete transaction
            raise errors.ServiceError.for_errno(data[0])

        TRANSACTION_SCHEMA.validate(data)

        for op, response_data in itertools.izip(request_transaction, data):
            op.load_response(response_data)
            self.append(op)

    def send(self, session):
        request = transport.TransactionRequest(self, session)
        return self._send(request)
        
    @utils.retry(RETRY_CONDITIONS)
    def _send(self, request):
        data = request.send().content
        response = self.__class__()
        response.deserialize(self, data)
        return response

class UserSession(Operation):
    schema = 'user-session.bundle.json'

    def request(self, user, hash):
        self['user'] = user
        if hash:
            self['hash'] = hash

class EphemeralUserSession(Operation):
    schema = 'user-session-ephemeral.bundle.json'

    def request(self, handle):
        self['handle'] = handle

class UserInformation(Operation):
    schema = 'user-information.bundle.json'

class UserUpdate(Operation):
    schema = 'user-update.bundle.json'

    def request(self, key, challenge):
        self['key'] = key
        self['challenge'] = challenge

class Files(Operation):
    schema = 'files.bundle.json'
    def request(self):
        self['c'] = 1 # TODO: Find out what this means

class FileGetInfo(Operation):
    schema = 'file-get-info.bundle.json'

    def request(self, handle, include_url = True):
        self['handle'] = handle
        self['include_url'] = int(include_url)

class PublicFileGetInfo(Operation):
    schema = 'public-file-get-info.bundle.json'

    def request(self, handle, include_url = True):
        self['handle'] = handle
        self['include_url'] = int(include_url)

class FileUpload(Operation):
    schema = 'file-upload.bundle.json'

    def request(self, size):
        self['size'] = size

class FileAdd(Operation):
    schema = 'file-add.bundle.json'

    def request(self, parent_handle, new_file, completion_token):
        self['parent'] = parent_handle
        self['files'] = [{
            'completion_token': completion_token,
            'type': new_file.type,
            'attrs': new_file.get_encrypted_attrs(),
            'key': new_file.get_serialized_key()
        }]

class FileMove(Operation):
    schema = 'file-move.bundle.json'
    def request(self, fileobj, new_parent):
        self['new_parent'] = new_parent.handle
        self['handle'] = fileobj.handle
        self['request_id'] = ''

class FileDelete(Operation):
    schema = 'file-delete.bundle.json'

    def request(self, file_handle):
        self['handle'] = file_handle
        self['request_id'] = ''

class FileGetPublicHandle(Operation):
    schema = 'file-get-public-handle.bundle.json'
    def request(self, handle):
        self['handle'] = handle

class PollServer(Operation):
    schema = 'server.bundle.json'
