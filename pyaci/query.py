# Copyright (c) 2015 Cisco Systems, Inc. All rights reserved.

"""
pyaci.query
~~~~~~~~~~~

This module contains support for querying the PyACI MIT.
"""

import operator
import os
import re
from collections import defaultdict

from flask import Flask, render_template, request
from flask.views import MethodView

from .utils import get_parent_dn


# TODO: Move to core.
def bfs_mit(mit, predicate=lambda mo: True):
    if mit.class_name != 'topRoot' and predicate(mit):
        yield mit
    for child in mit._children.values():
        for mo in bfs_mit(child):
            if predicate(mo):
                yield mo


def is_dn(value):
    return str(value).find('/') != -1


class Index:
    def __init__(self, mit, name):
        self._mit = mit
        self._name = name
        self._objects_by_dn = {}
        self._objects_by_class = defaultdict(list)

        for mo in bfs_mit(mit):
            self._objects_by_dn[mo.dn] = mo
            self._objects_by_class[mo.class_name].append(mo)

    @property
    def mit(self):
        return self._mit

    @property
    def name(self):
        return self._name

    def query_by_dn(self, dn, **kwargs):
        mo = self._objects_by_dn.get(dn, None)
        if mo is None:
            return []

        rsp_subtree = kwargs.get('rsp-subtree', [])
        if not rsp_subtree:
            return [mo]
        elif 'children' in rsp_subtree:
            return [x for x in mo._children.values()]
        else:
            return []

    def query_by_class(self, class_name, **kwargs):
        # TODO: Handle invalid class names.
        query_target_filter = kwargs.get('query-target-filter', [])
        if query_target_filter:
            try:
                match = re.match(r'(.*)\((.*),"(.*)"\)', query_target_filter[0])
                if match:
                    op = match.group(1)
                    prop_name = match.group(2)
                    tokens = prop_name.split('.')
                    cl_name = tokens[0]
                    prop_name = tokens[1]
                    value = match.group(3)

                    def pred(mo):
                        if mo.class_name != cl_name:
                            return False
                        return getattr(operator, op)(getattr(mo, prop_name), value)

                    return filter(pred, self._objects_by_class[class_name])
            except Exception as e:
                print(e)

        return self._objects_by_class[class_name]


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
    def app_indices(self):
        return sorted(self.app._indices.keys())


class DnView(AView):
    def get(self, dn):
        result = self.index.query_by_dn(dn, **request.args)
        return render_template(
            'mo-view.html',
            mos=result,
            indexName=self.index.name,
            indices=self.app_indices,
            currentDn=dn,
        )


class ClassView(AView):
    def get(self, class_name):
        result = self.index.query_by_class(class_name, **request.args)
        return render_template(
            'mo-view.html',
            mos=result,
            indexName=self.index.name,
            indices=self.app_indices,
            currentClassName=class_name,
        )


class AuditView(AView):
    def get(self, dn):
        query_opt = {'query-target-filter': [f'eq(aaaModLR.affected,"{dn}")']}
        result = self.index.query_by_class('aaaModLR', **query_opt)

        def sort_key(mo):
            return int(mo.txId)

        return render_template(
            'audit-view.html',
            mos=sorted(result, key=sort_key),
            indexName=self.index.name,
            indices=self.app_indices,
        )


class App:
    def __init__(self):
        self._indices = {}
        template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
        static_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
        self._app = Flask(
            'pyaci query app',
            static_folder=static_folder,
            template_folder=template_folder,
        )
        self._app.add_template_test(is_dn, 'dn')
        self._app.add_template_filter(get_parent_dn, 'parentDn')

    def add_index(self, index):
        # TODO: Handle duplicate index.
        self._indices[index.name] = index
        self._app.add_url_rule(
            f'/{index.name}/dn/<path:dn>',
            view_func=DnView.as_view(f'dn_view_{index.name}', index, self),
            methods=['GET'],
        )
        self._app.add_url_rule(
            f'/{index.name}/class/<class_name>',
            view_func=ClassView.as_view(f'class_view_{index.name}', index, self),
            methods=['GET'],
        )

        if index.name == 'audit':
            self._app.add_url_rule(
                f'/{index.name}/affected/<path:dn>',
                view_func=AuditView.as_view(f'affected_view_{index.name}', index, self),
                methods=['GET'],
            )

    def indices(self):
        return self._indices

    def run(self, debug=False):
        self._app.debug = debug
        self._app.run(host='0.0.0.0')
