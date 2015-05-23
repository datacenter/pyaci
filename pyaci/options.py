# Copyright (c) 2014, 2015 Cisco Systems, Inc. All rights reserved.

"""
pyaci.options
~~~~~~~~~~~~~~~~~~~

This module contains helpers to construct REST API options for PyACI.
"""


class ApiOptions(dict):
    """Dict like data structure capturing REST API options."""

    def __and__(self, other):
        return ApiOptions(self.items() + other.items())

"""Query immediate children."""
children = ApiOptions([('query-target', 'children')])

"""Query the entire subtree."""
subtree = ApiOptions([('query-target', 'subtree')])

"""Include all the faults along with the entire subtree."""
faults = ApiOptions([('rsp-subtree-include', 'faults,no-scoped')])

"""Query audit logs."""
auditLogs = ApiOptions([('rsp-subtree-include', 'audit-logs,no-scoped')])


def subtreeClass(className):
    """Query subtree class."""
    return (ApiOptions([('query-target', 'subtree')]) &
            ApiOptions([('target-subtree-class', className)]))


def childClass(className):
    """Query child class."""
    return (ApiOptions([('query-target', 'children')]) &
            ApiOptions([('target-subtree-class', className)]))
