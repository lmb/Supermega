from __future__ import absolute_import

from .models import User, Keystore
from .utils import retry
from itertools import count

import requests
import logging

from . import errors
from . import protocol
from . import transport
from . import models

__all__ = [ 'Session' ]

class Session(object):
    def __init__(self):
        self.sequence = count(0)
        self.keystore = models.Keystore()
        self.datastore = models.Datastore()

        # self._poller = gevent.Greenlet(self._poll_server)

        self._reqs_session = requests.Session()
        self._reqs_session.stream = True
        self._reqs_session.params['ssl'] = 1

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

    def __str__(self):
        if not self.user:
            return self.__repr__()

        return "%s for user '%s'" % (self.__name__, self.user.username)

    def login(self, username, password):
        self.user = User(self, username, password)

        req = protocol.UserSessionRequest(self.user)
        res = req.send(self)
        self.user.decrypt_session_id(**res.as_dict())

        self._reqs_session.params['sid'] = self.user.session_id

        req = protocol.UserGetRequest()
        res = req.send(self)
        self.user.update(**res.as_dict())

    def init_datastore(self):
        req = protocol.FilesRequest()
        res = req.send(self)

        self._maxaction = res.maxaction

        for data in res.files:
            meta = models.Meta.for_data(self.keystore, data)
            self.datastore.add(meta)

    def download(self, func, file, *args, **kwargs):
        if isinstance(file, basestring):
            (handle, cipher_info) = models.File.parse_download_url(file)

            req = protocol.PublicFileDownloadRequest(handle)
            res = req.send(self)

            file = models.File(self.keystore, res.as_dict(), cipher_info=cipher_info)
        else:
            req = protocol.FileDownloadRequest(file)
            res = req.send(self)

        req = requests.get(res.url, stream=True)
        func(file, file.decrypt_from_stream(req.raw), *args, **kwargs)

    def download_to_file(self, file, handle):
        self.download(self._to_file, file, handle)

    @staticmethod
    def _to_file(file, chunks, handle):
        for chunk in chunks:
            handle.write(chunk)

    def _update_filetree(self, res):
        self._maxaction = res.maxaction

        for data in res.files:
            meta = models.Meta.for_data(self.keystore, data)
            self.datastore.add(meta)

    @retry(protocol.RETRY_CONDITIONS)
    def _poll_server(self):
        while True:
            # If we're running, _maxaction is guaranteed to be set
            req = transport.ServerRequest(self._maxaction, self)
            content = req.send().content

            res = protocol.ServerResponse()
            res.load(req, content)

            if hasattr(res, 'wait_url'):
                self._reqs_session.get(res.wait_url, params = {'ssl': None, 'sid': None})
            else:
                # TODO: Handle opcode
                print "opcode = {}, maxaction = {}".format(res.opcode, res.maxaction)
                self._maxaction = res.maxaction
    