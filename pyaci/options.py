# Copyright (c) 2014, 2015 Cisco Systems, Inc. All rights reserved.

"""
pyaci.options
~~~~~~~~~~~~~~~~~~~

This module contains helpers to construct REST API options for PyACI.
"""


class api_options(dict):
    """Dict like data structure capturing REST API options."""

    def __and__(self, other):
        return api_options(self, **other)


"""Query immediate children."""
children = api_options([('query-target', 'children')])

"""Query the entire subtree."""
subtree = api_options([('query-target', 'subtree')])


def rsp_subtree_include(level):
    """Query additional contained objects along in the response e.g. relations, stats, faults"""
    return api_options([('rsp-subtree-include', level)])


def rsp_subtree_class(className):
    """Query specific"""
    return api_options([('rsp-subtree', 'full')]) & api_options([('rsp-subtree-class', className)])


def rsp_prop_include(propType):
    """Query ."""
    return api_options([('rsp-prop-include', propType)])


"""Query the object with all the children."""
rsp_subtree_children = api_options([('rsp-subtree', 'children')])

"""Query the object with the entire subtree."""
rsp_subtree_full = api_options([('rsp-subtree', 'full')])

"""Include all the faults along with the entire subtree."""
faults = api_options([('rsp-subtree-include', 'faults,no-scoped')])

"""Query audit logs."""
audit_logs = api_options([('rsp-subtree-include', 'audit-logs,no-scoped')])

"""Get count."""
count = api_options([('rsp-subtree-include', 'count')])

"""Subscribe to WebSocket notifications."""
subscribe = api_options([('subscription', 'yes')])


def subtree_class(className):
    """Query subtree class."""
    return api_options([('query-target', 'subtree')]) & api_options([('target-subtree-class', className)])


def child_class(className):
    """Query child class."""
    return api_options([('query-target', 'children')]) & api_options([('target-subtree-class', className)])


def order_by(property):
    """Order the query result by the given property."""
    return api_options([('order-by', property)])


def page(value):
    """Results from only the given page."""
    return api_options([('page', value)])


def page_size(value):
    """Number of objects per page."""
    return api_options([('page-size', value)])


"""Subscribe to queries."""
subscribe = api_options([('subscription', 'yes')])


def filter(filt):
    """Restrict to the specified filter"""
    return api_options([('query-target-filter', str(filt))])


def subtree_filter(filt):
    """Restrict to the specified filter"""
    return (
        api_options([('rsp-subtree-filter', str(filt))])
        & api_options([('rsp-subtree-include', 'required')])
        & api_options([('rsp-subtree', 'full')])
    )
