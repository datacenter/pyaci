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


def rspSubtreeInclude(level):
    """Query additional contained objects along in the response e.g. relations, stats, faults"""
    return ApiOptions([('rsp-subtree-include', level)])


def rspSubtreeClass(className):
    """Query specific"""
    return (ApiOptions([('rsp-subtree', 'full')]) &
            ApiOptions([('rsp-subtree-class', className)]))


def rspPropInclude(propType):
    """Query ."""
    return ApiOptions([('rsp-prop-include', propType)])


"""Query the object with all the children."""
rspSubtreeChildren = ApiOptions([('rsp-subtree', 'children')])

"""Query the object with the entire subtree."""
rspSubtreeFull = ApiOptions([('rsp-subtree', 'full')])

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


def subtreeFilter(filt):
    """Restrict to the specified filter"""
    return (ApiOptions([('rsp-subtree-filter', str(filt))]) &
            ApiOptions([('rsp-subtree-include', 'required')]) &
            ApiOptions([('rsp-subtree', 'full')]))
