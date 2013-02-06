import requests
import errors

from utils import retry
from itertools import chain

class APIRequest(object):
    API_URL = 'https://g.api.mega.co.nz'
    
    def __init__(self, session, params = {}):
        self._session = session
        self._params = params
        self._data = None
        self._method = 'POST'

    def send(self, timeout=10):
        url = "%s/%s" % (self.API_URL, self.ENDPOINT)

        headers = {'Content-type': 'application/json'}

        params = self._params
        params['id'] = next(self._session.sequence)

        res = self._session._reqs_session.request(self._method, url,
            timeout=timeout, params = params, headers = headers, data = self._data)

        if res.status_code != 200:
            raise errors.HTTPStatusError.for_status(res.status_code)

        return res

class TransactionRequest(APIRequest):
    ENDPOINT = 'cs'

    def __init__(self, transaction, *args, **kwargs):
        super(TransactionRequest, self).__init__(*args, **kwargs)
        self._data = transaction.serialize()

# TODO: Rename this
class ServerRequest(APIRequest):
    ENDPOINT = 'sc'

    def __init__(self, maxaction, *args, **kwargs):
        super(ServerRequest, self).\
            __init__(params={'sn': maxaction}, *args, **kwargs)
