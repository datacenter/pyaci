# Copyright (c) 2014, 2015 Cisco Systems, Inc. All rights reserved.

"""
pyaci.options
~~~~~~~~~~~~~~~~~~~

This module contains helpers to construct REST API options for PyACI.
"""


class ApiOptions(dict):
    """Dict like data structure capturing REST API options."""

    def __and__(self, other):
        return ApiOptions(self, **other)


"""Query immediate children."""
children = ApiOptions([('query-target', 'children')])

"""Query the entire subtree."""
subtree = ApiOptions([('query-target', 'subtree')])

"""Include all the faults along with the entire subtree."""
faults = ApiOptions([('rsp-subtree-include', 'faults,no-scoped')])

"""Query audit logs."""
auditLogs = ApiOptions([('rsp-subtree-include', 'audit-logs,no-scoped')])

"""Get count."""
count = ApiOptions([('rsp-subtree-include', 'count')])

"""Subscribe to WebSocket notifications."""
subscribe = ApiOptions([('subscription', 'yes')])


def subtreeClass(className):
    """Query subtree class."""
    return (ApiOptions([('query-target', 'subtree')]) &
            ApiOptions([('target-subtree-class', className)]))


def childClass(className):
    """Query child class."""
    return (ApiOptions([('query-target', 'children')]) &
            ApiOptions([('target-subtree-class', className)]))


def orderBy(property):
    """Order the query result by the given property."""
    return ApiOptions([('order-by', property)])


def page(value):
    """Results from only the given page."""
    return ApiOptions([('page', value)])


def pageSize(value):
    """Number of objects per page."""
    return ApiOptions([('page-size', value)])


"""Subscribe to queries."""
subscribe = ApiOptions([('subscription', 'yes')])


def filter(filt):
    """Restrict to the specified filter"""
    return ApiOptions([('query-target-filter', str(filt))])
