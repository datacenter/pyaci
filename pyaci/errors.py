# -*- coding: utf-8 -*-

"""
pyaci.errors
~~~~~~~~~~~~~~~~~~~

This module contains the set of PyACI exceptions.
"""


class Error(Exception):
    """An ambigious error occurred."""
    pass


class MetaError(Error):
    """A meta error occurred."""
    pass


class MoError(Error):
    """An MO error occurred."""
    pass


class ResourceError(Error):
    """A resource error occurred."""
    pass


class RestError(Error):
    """A REST error occurred."""
    pass


class UserError(Error):
    """A user caused error occurred."""
    pass
