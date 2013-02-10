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

    @retry(protocol.RETRY_CONDITIONS)
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
    