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


def orderBy(property):
    """Order the query result by the given property."""
    return ApiOptions([('order-by', property)])


def page(value):
    """Results from only the given page."""
    return ApiOptions([('page', value)])


def pageSize(value):
    """Number of objects per page."""
    return ApiOptions([('page-size', value)])


def filter(filt):
    """Restrict to the specified filter"""
    return ApiOptions([('query-target-filter', str(filt))])


class Filter(object):
    def __invert__(self):
        return Not(self)

    def __and__(self, other):
        return And(self, other)

    def __or__(self, other):
        return Or(self, other)

    def __xor__(self, other):
        return Xor(self, other)


class UnaryFilter(Filter):
    def __init__(self, value):
        self._value = value

    def __str__(self):
        if isinstance(self._value, str):
            value = '"{}"'.format(self._value)
        else:
            value = self._value
        return '{}({})'.format(self._operator, value)


class Not(UnaryFilter):
    _operator = 'not'


class True(UnaryFilter):
    _operator = 'true'


class False(UnaryFilter):
    _operator = 'false'


class AnyBit(UnaryFilter):
    _operator = 'anybit'


class AllBit(UnaryFilter):
    _operator = 'allbit'


class BinaryFilter(Filter):
    def __init__(self, left, right):
        self._left = left
        self._right = right

    def __str__(self):
        if isinstance(self._right, str):
            right = '"{}"'.format(self._right)
        else:
            right = self._right
        return '{}({},{})'.format(self._operator, self._left, right)


class Eq(BinaryFilter):
    _operator = 'eq'


class Ne(BinaryFilter):
    _operator = 'ne'


class Lt(BinaryFilter):
    _operator = 'lt'


class Gt(BinaryFilter):
    _operator = 'gt'


class Le(BinaryFilter):
    _operator = 'le'


class Ge(BinaryFilter):
    _operator = 'ge'


class Wcard(BinaryFilter):
    _operator = 'wcard'


class And(BinaryFilter):
    _operator = 'and'


class Or(BinaryFilter):
    _operator = 'or'


class Xor(BinaryFilter):
    _operator = 'xor'


class TernaryFilter(Filter):
    def __init__(self, left, middle, right):
        self._left = left
        self._middle = middle
        self._right = right

    def __str__(self):
        return '{}({},"{}","{}")'.format(
            self._operator, self._left, self._middle, self._right)


class Bw(TernaryFilter):
    _operator = 'bw'


# FIXME (2015-05-22, Praveen Kumar): Learn about pholder, and passive
# filters and implement.
