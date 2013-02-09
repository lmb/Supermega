import os.path
import json
from itertools import izip, ifilter
from requests.exceptions import Timeout

from . import transport
from . import errors
from . import utils
from . import schemata

TRANSACTION_SCHEMA = schemata.Schema.from_file('transaction.json')
RETRY_CONDITIONS = (Timeout, errors.RetryRequest, errors.HTTP500Error)

# TODO: Maybe inherit from dict?
class Operation(object):
    OPCODE_KEY = 'a'
    _data = {}

    def read_schema(self, part, schema):
        self._schema, self._mapping = schemata.load_bundle(schema, part)

    def is_mapped_attr(self, attr):
        return attr in self._mapping

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
        self.opcode = (self._schema.definition['properties']
            [Operation.OPCODE_KEY]['pattern'])

    def validate_attr(self, attr, value):
        mapped = self._mapping[attr] and (self._mapping[attr],) or ()
        self._schema.validate(value, mapped)

    def as_serializable_dict(self):
        data = { self._mapping[attr]: self._data[attr] for attr in \
            ifilter(self._data.__contains__, self._mapping.iterkeys()) }
        data[Operation.OPCODE_KEY] = self.opcode

        self._schema.validate(data)
        return data

    def __setitem__(self, attr, value):
        # TODO: Possibly restrict setting to mapped values
        if self.is_mapped_attr(attr):
            self.validate_attr(attr, value)

        self._data[attr] = value

    def send(self, session):
        transaction = Transaction(self)
        return transaction.send(session)[0]

class Response(Operation):
    """Represents a response from the MEGA servers."""

    def load(self, request, data):
        self.request = request
        self._schema.validate(data)
        self._load(self._data, data, self._mapping)

    def _load(self, container, data, mapping):
        for attr_to, attr_from in mapping.iteritems():
            if not attr_from:
                # Take data verbatim
                container[attr_to] = data

            elif isinstance(attr_from, (list, tuple)):
                # Map nested attributes
                mapping = attr_from[1]
                attr_from = attr_from[0]

                if isinstance(data[attr_from], list):
                    # Map a list of objects
                    container[attr_to] = []
                    for entry in data[attr_from]:
                        mapped_entry = {}
                        self._load(mapped_entry, entry, mapping)
                        container[attr_to].append(mapped_entry)
                else:
                    # Map an object
                    container[attr_to] = {}
                    self._load(container[attr_to], data[attr_from], mapping)

            elif attr_from in data:
                # Map a -> b
                container[attr_to] = data[attr_from]

    def read_schema(self, *args, **kwargs):
        super(Response, self).read_schema('response', *args, **kwargs)

    def as_dict(self):
        """Returns all response data that has been mapped."""
        return { key: self._data[key] for key in self._mapping.iterkeys() }

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

    def unserialize(self, request, data):
        data = json.loads(data)

        # The server seems to return either -errno or [-errno]
        if isinstance(data, (int, long)):
            raise errors.ServiceError.for_errno(data)
        if len(data) == 1 and isinstance(data[0], (int, long)):
            # TODO: This only catches the first error in a complete transaction
            raise errors.ServiceError.for_errno(data[0])

        TRANSACTION_SCHEMA.validate(data)

        for req, response_data in izip(request, data):
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
        response.unserialize(self, data)
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
    def __init__(self, file_meta):
        self.read_schema('file-download.bundle.json')

        self['handle'] = file_meta.handle
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
class ServerResponse(Response):
    def __init__(self):
        self.read_schema('server.bundle.json')
