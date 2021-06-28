"""Define package errors."""


class RinnaiError(Exception):
    """Define a base error."""

    pass


class RequestError(RinnaiError):
    """Define an error related to invalid requests."""

    pass