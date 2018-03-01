# Copyright (c) 2015 Cisco Systems, Inc. All rights reserved.

"""
pyaci.query
~~~~~~~~~~~

This module contains support for querying the PyACI MIT.
"""

from collections import defaultdict
from flask import Flask, request, render_template
from flask.views import MethodView
from .utils import getParentDn
import operator
import os
import re


# TODO: Move to core.
def bfsMit(mit, predicate=lambda mo: True):
    if mit.ClassName != 'topRoot' and predicate(mit):
        yield mit
    for child in mit._children.values():
        for mo in bfsMit(child):
            if predicate(mo):
                yield mo


def isDn(value):
    return str(value).find('/') != -1


class Index(object):
    def __init__(self, mit, name):
        self._mit = mit
        self._name = name
        self._objectsByDn = {}
        self._objectsByClass = defaultdict(list)

        for mo in bfsMit(mit):
            self._objectsByDn[mo.Dn] = mo
            self._objectsByClass[mo.ClassName].append(mo)

    @property
    def mit(self):
        return self._mit

    @property
    def name(self):
        return self._name

    def queryByDn(self, dn, **kwargs):
        mo = self._objectsByDn.get(dn, None)
        if mo is None:
            return []

        rspSubtree = kwargs.get('rsp-subtree', [])
        if not rspSubtree:
            return [mo]
        elif 'children' in rspSubtree:
            return [x for x in mo._children.values()]
        else:
            return []

    def queryByClass(self, className, **kwargs):
        # TODO: Handle invalid class names.
        queryTargetFilter = kwargs.get('query-target-filter', [])
        if queryTargetFilter:
            try:
                match = re.match('(.*)\((.*),"(.*)"\)', queryTargetFilter[0])
                if match:
                    op = match.group(1)
                    propName = match.group(2)
                    tokens = propName.split('.')
                    clName = tokens[0]
                    propName = tokens[1]
                    value = match.group(3)

                    def pred(mo):
                        if mo.ClassName != clName:
                            return False
                        return getattr(operator, op)(getattr(mo, propName),
                                                     value)
                    return filter(pred, self._objectsByClass[className])
            except Exception as e:
                print(e)

        return self._objectsByClass[className]


class AView(MethodView):
    def __init__(self, index, app):
        self._index = index
        self._app = app

    @property
    def index(self):
        return self._index

    @property
    def app(self):
        return self._app

    @property
    def appIndices(self):
        return sorted(self.app._indices.keys())


class DnView(AView):
    def get(self, dn):
        result = self.index.queryByDn(dn, **request.args)
        return render_template('mo-view.html', mos=result,
                               indexName=self.index.name,
                               indices=self.appIndices,
                               currentDn=dn)


class ClassView(AView):
    def get(self, className):
        result = self.index.queryByClass(className, **request.args)
        return render_template('mo-view.html', mos=result,
                               indexName=self.index.name,
                               indices=self.appIndices,
                               currentClassName=className)


class AuditView(AView):
    def get(self, dn):
        queryOpt = {
            'query-target-filter': ['eq(aaaModLR.affected,"{}")'.format(dn)]
        }
        result = self.index.queryByClass('aaaModLR', **queryOpt)

        def sortKey(mo):
            return int(mo.txId)

        return render_template('audit-view.html',
                               mos=sorted(result, key=sortKey),
                               indexName=self.index.name,
                               indices=self.appIndices)


class App(object):
    def __init__(self):
        self._indices = {}
        templateFolder = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'templates')
        staticFolder = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'static')
        self._app = Flask('pyaci Query App',
                          static_folder=staticFolder,
                          template_folder=templateFolder)
        self._app.add_template_test(isDn, 'Dn')
        self._app.add_template_filter(getParentDn, 'parentDn')

    def addIndex(self, index):
        # TODO: Handle duplicate index.
        self._indices[index.name] = index
        self._app.add_url_rule(
            '/{}/dn/<path:dn>'.format(index.name),
            view_func=DnView.as_view('dn_view_{}'.format(index.name),
                                     index, self),
            methods=['GET']
        )
        self._app.add_url_rule(
            '/{}/class/<className>'.format(index.name),
            view_func=ClassView.as_view('class_view_{}'.format(index.name),
                                        index, self),
            methods=['GET']
        )

        if index.name == 'audit':
            self._app.add_url_rule(
                '/{}/affected/<path:dn>'.format(index.name),
                view_func=AuditView.as_view(
                    'affected_view_{}'.format(index.name),
                    index, self),
                methods=['GET']
            )

    def indices(self):
        return self._indices

    def run(self, debug=False):
        self._app.debug = debug
        self._app.run(host='0.0.0.0')
