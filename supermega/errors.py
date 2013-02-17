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

class CorruptFile(SupermegaException):
    """A file download was corrupted"""
    pass

class ServiceError(SupermegaException):
    """The MEGA service has indicated an error."""

    def __init__(self, errno, message = None, *args):
        super(SupermegaException, self).\
            __init__(message or self.__doc__.format(errno=errno), *args)
        self.errno = errno

    @classmethod
    def for_errno(cls, errno, *args, **kwargs):
        return cls.ERRORS.get(errno, UnknownError)(errno, *args, **kwargs)

class UnknownError(ServiceError):
    """The server indicated a status that is unknown to the library: {errno}."""
    pass

### HTTP Errors
class HTTPStatusError(ServiceError):
    """The request failed with status {errno}"""

    @classmethod
    def for_status(cls, status, *args, **kwargs):
        return cls.STATUS_CODES.get(status, HTTPStatusError)(status, *args, **kwargs)