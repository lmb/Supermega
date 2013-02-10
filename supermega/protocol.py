import os.path
import json
import copy
import itertools
import requests.exceptions

from . import transport
from . import errors
from . import utils
from . import schemata

TRANSACTION_SCHEMA = schemata.Schema.from_file('transaction.json')
RETRY_CONDITIONS = (requests.exceptions.Timeout, errors.RetryRequest,
    errors.HTTP500Error)

# TODO: Maybe inherit from dict?
class Operation(object):
    OPCODE_KEY = 'a'
    _data = {}

    def read_schema(self, part, schema):
        self._bundle = schemata.SchemaBundle.from_file(schema, part)

    def get(self, *args, **kwargs):
        return self._data.get(*args, **kwargs)

    def __getitem__(self, key):
        return self._data[key]

    def __contains__(self, key):
        return self._data.__contains__(key)

class Request(Operation):
    """Represents a request to the MEGA servers."""

    def read_schema(self, *args, **kwargs):
        super(Request, self).read_schema('request', *args, **kwargs)
        self.opcode = (self._bundle.schema.definition['properties']
            [Operation.OPCODE_KEY]['pattern'])

    def as_serializable_dict(self):
        data = self._bundle.translate(self._data)
        data[Operation.OPCODE_KEY] = self.opcode
        self._bundle.schema.validate(data)
        return data

    def __setitem__(self, attr, value):
        self._bundle.validate(value, (attr,))
        self._data[attr] = value

    def send(self, session):
        transaction = Transaction(self)
        return transaction.send(session)[0]

class Response(Operation):
    """Represents a response from the MEGA servers."""

    def load(self, request, data):
        self.request = request
        self._bundle.schema.validate(data)
        self._data = self._bundle.translate(data)

    def read_schema(self, *args, **kwargs):
        super(Response, self).read_schema('response', *args, **kwargs)

    def as_dict(self):
        """Returns all response data."""
        return copy.deepcopy(self._data)

def is_response_to(request_class):
    def decorate(response_class):
        request_class.RESPONSE = response_class
        return response_class
    return decorate

class Transaction(list):
    class Encoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, Request):
                return obj.as_serializable_dict()

            return super(json.JSONEncoder, self).default(obj)

    def __init__(self, *args):
        super(Transaction, self).__init__(args)

    def serialize(self):
        return json.dumps(self, cls=self.Encoder)

    def deserialize(self, request, data):
        data = json.loads(data)

        # The server seems to return either -errno or [-errno]
        if isinstance(data, (int, long)):
            raise errors.ServiceError.for_errno(data)
        if len(data) == 1 and isinstance(data[0], (int, long)) and data[0] < 0:
            # TODO: This only catches the first error in a complete transaction
            raise errors.ServiceError.for_errno(data[0])

        TRANSACTION_SCHEMA.validate(data)

        for req, response_data in itertools.izip(request, data):
            res = req.RESPONSE()
            res.load(req, response_data)
            self.append(res)

    def send(self, session):
        request = transport.TransactionRequest(self, session)
        return self._send(request)
        
    @utils.retry(RETRY_CONDITIONS)
    def _send(self, request):
        data = request.send().content
        response = self.__class__()
        response.deserialize(self, data)
        return response

    # def send(self, session, notify, *args, **kwargs):
    #   greenlet = gevent.Greenlet(self.send_wait, session)
    #   greenlet.link_value(utils.link_unwrap(notify, args, kwargs))
    #   session._pool.start(greenlet)

#############
class UserSessionRequest(Request):
    def __init__(self, user, hash):
        self.read_schema('user-session.bundle.json')

        self['user'] = user
        if hash:
            self['hash'] = hash

@is_response_to(UserSessionRequest)
class UserSessionResponse(Response):
    def __init__(self):
        self.read_schema('user-session.bundle.json')

class EphemeralUserSessionRequest(Request):
    def __init__(self, handle):
        self.read_schema('user-session-ephemeral.bundle.json')
        self['handle'] = handle

@is_response_to(EphemeralUserSessionRequest)
class EphemeralUserSessionResponse(Response):
    def __init__(self):
        self.read_schema('user-session-ephemeral.bundle.json')

#############
class UserInformationRequest(Request):
    def __init__(self):
        self.read_schema('user-information.bundle.json')

@is_response_to(UserInformationRequest)
class UserInformationResponse(Response):
    def __init__(self):
        self.read_schema('user-information.bundle.json')

#############
class UserUpdateRequest(Request):
    def __init__(self, key, challenge):
        self.read_schema('user-update.bundle.json')
        self['key'] = key
        self['challenge'] = challenge

@is_response_to(UserUpdateRequest)
class UserUpdateReponse(Response):
    def __init__(self):
        self.read_schema('user-update.bundle.json')

#############
class FilesRequest(Request):
    def __init__(self):
        self.read_schema('files.bundle.json')
        self['c'] = 1 # TODO: Find out what this means

@is_response_to(FilesRequest)
class FilesResponse(Response):
    def __init__(self):
        self.read_schema('files.bundle.json')

##############
class FileDownloadRequest(Request):
    def __init__(self, file):
        self.read_schema('file-download.bundle.json')

        self['handle'] = file.handle
        self['g'] = 1 # TODO: What does this mean?

@is_response_to(FileDownloadRequest)
class FileDownloadResponse(Response):
    def __init__(self):
        self.read_schema('file-download.bundle.json')

##############
class PublicFileDownloadRequest(Request):
    def __init__(self, handle):
        self.read_schema('file-download-public.bundle.json')

        self['handle'] = handle
        self['g'] = 1

@is_response_to(PublicFileDownloadRequest)
class FileDownloadReponse(Response):
    def __init__(self):
        self.read_schema('file-download-public.bundle.json')

##############
class FileUploadRequest(Request):
    def __init__(self, size):
        self.read_schema('file-upload.bundle.json')
        self['size'] = size

@is_response_to(FileUploadRequest)
class FileUploadResponse(Response):
    def __init__(self):
        self.read_schema('file-upload.bundle.json')

##############
class FileAddRequest(Request):
    def __init__(self, parent, new_file, completion_token):
        self.read_schema('file-add.bundle.json')

        self['parent'] = parent.handle
        self['files'] = [{
            'completion_token': completion_token,
            'type': new_file.type,
            'attrs': new_file.get_encrypted_attrs(),
            'key': new_file.get_serialized_key()
        }]

@is_response_to(FileAddRequest)
class FileAddResponse(Response):
    def __init__(self):
        self.read_schema('file-add.bundle.json')

##############
class FileMoveRequest(Request):
    def __init__(self, fileobj, new_parent):
        self.read_schema('file-move.bundle.json')
        self['new_parent'] = new_parent.handle
        self['handle'] = fileobj.handle
        self['request_id'] = ''

@is_response_to(FileMoveRequest)
class FileMoveResponse(Response):
    def __init__(self):
        self.read_schema('file-move.bundle.json')

##############
class FileDeleteRequest(Request):
    def __init__(self, file):
        self.read_schema('file-delete.bundle.json')
        self['handle'] = file.handle
        self['request_id'] = ''

@is_response_to(FileDeleteRequest)
class FileDeleteResponse(Response):
    def __init__(self):
        self.read_schema('file-delete.bundle.json')

##############
class ServerResponse(Response):
    def __init__(self):
        self.read_schema('server.bundle.json')
