"""
PyACI - Python Bindings for ACI REST API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PyACI is a simplified take on providing Python bindings for Cisco ACI
REST API.

"""

__title__ = 'pyaci'
__version__ = '1.0'
__build__ = 1
__author__ = 'Praveen Kumar'
__license__ = 'Apache 2.0'
__copyright__ = 'Copyright (c) 2015 Cisco Systems, Inc. All rights reserved.'


from .core import Node
import pyaci.options
import pyaci.filters
