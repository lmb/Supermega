from .utils import registry

class SupermegaException(Exception):
    """Supermega exception base class."""
    pass

class ValidationError(SupermegaException):
    """Validating a JSON schema failed."""

    def __init__(self, validation_exception, schema, instance):
        self.original_exception = validation_exception
        self.message = validation_exception.message
        self.schema = schema
        self.instance = instance

    def __str__(self):
        return "{} (schema: {}, instance: {})".format(self.message, self.schema.name, self.instance)

class ServiceError(SupermegaException):
    """The MEGA service has indicated an error."""

    def __init__(self, errno, message = None, *args):
        super(SupermegaException, self).\
            __init__(message or self.__doc__.format(errno=errno), *args)
        self.errno = errno

    @classmethod
    def for_errno(cls, errno, *args, **kwargs):
        return cls.ERRORS.get(errno, UnknownError)(errno, *args, **kwargs)

service_error = registry(ServiceError, 'ERRORS')

class UnknownError(ServiceError):
    """The server indicated a status that is unknown to the library: {errno}."""
    pass

@service_error(-3)
class RetryRequest(ServiceError):
    """The server is too busy and requests a retry"""
    pass

@service_error(-5)
class UploadFailed(ServiceError):
    """The upload failed"""
    pass

@service_error(-6)
class ConcurrentIPsExceeded(ServiceError):
    """Too many different IPs are concurrently accessin this upload URL"""
    pass

@service_error(-7)
class InvalidRange(ServiceError):
    """An invalid range header was specified"""
    pass

@service_error(-8)
class UploadURLExpired(ServiceError):
    """The upload URL has expired"""
    pass

@service_error(-9)
class ObjectNotFound(ServiceError):
    """Object (typically node or user) not found"""
    pass

@service_error(-10)
class CircularLinkingAttempted(ServiceError):
    """A circular link was denied"""
    pass

@service_error(-11)
class AccessViolation(ServiceError):
    """An access violation occured (e.g. writing to a read-only share)"""

@service_error(-12)
class ObjectExists(ServiceError):
    """The object already exists on the server"""
    pass

@service_error(-13)
class ObjectIncomplete(ServiceError):
    """The accessed object is incomplete"""
    pass

@service_error(-15)
class InvalidSessionId(ServiceError):
    """The server indicates that the provided session id is invalid"""
    pass

@service_error(-16)
class UserBlocked(ServiceError):
    """The user has been blocked"""
    pass

@service_error(-17)
class QuotaExceeded(ServiceError):
    """The user quota has been exceeded"""
    pass

@service_error(-18)
class TemporarilyUnavailable(ServiceError):
    """The resource is temporarily unavailable"""
    # TODO: Should this be a retry condition?
    pass

### HTTP Errors
class HTTPStatusError(ServiceError):
    """The request failed with status {errno}"""

    @classmethod
    def for_status(cls, status, *args, **kwargs):
        return cls.STATUS_CODES.get(status, HTTPStatusError)(status, *args, **kwargs)

http_error = registry(HTTPStatusError, 'STATUS_CODES')

@http_error(500)
class HTTP500Error(HTTPStatusError):
    """The server is too busy"""
    pass