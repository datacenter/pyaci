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


# TODO: Move to core.
def bfsMit(mit):
    if mit.ClassName != 'topRoot':
        yield mit
    for child in mit._children.values():
        for mo in bfsMit(child):
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
        return self._objectsByClass[className]


class AView(MethodView):
    def __init__(self, index):
        self._index = index

    @property
    def index(self):
        return self._index


class DnView(AView):
    def get(self, dn):
        result = self.index.queryByDn(dn, **request.args)
        return render_template('mo-view.html', mos=result,
                               indexName=self.index.name)


class ClassView(AView):
    def get(self, className):
        result = self.index.queryByClass(className)
        return render_template('mo-view.html', mos=result,
                               indexName=self.index.name)


class App(object):
    def __init__(self):
        self._indices = {}
        self._app = Flask('pyaci Query App')
        self._app.add_template_test(isDn, 'Dn')
        self._app.add_template_filter(getParentDn, 'parentDn')

    def addIndex(self, index):
        # TODO: Handle duplicate index.
        self._indices[index.name] = index
        self._app.add_url_rule(
            '/{}/dn/<path:dn>'.format(index.name),
            view_func=DnView.as_view('dn_view', index),
            methods=['GET']
        )
        self._app.add_url_rule(
            '/{}/class/<className>'.format(index.name),
            view_func=ClassView.as_view('class_view', index),
            methods=['GET']
        )

    def run(self, debug=False):
        self._app.debug = debug
        self._app.run()
