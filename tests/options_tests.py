import logging
import os
import sys

# pylint: disable=unused-import
import sure  # flake8: noqa

paths = [
    '..',
]
for path in paths:
    sys.path.append(os.path.abspath(path))

import pyaci

logging.captureWarnings(True)


def testSubtreeClass():
    opt = pyaci.options.subtree_class('fvSubnet')
    opt['query-target'].should.equal('subtree')
    opt['target-subtree-class'].should.equal('fvSubnet')


def testChildClass():
    opt = pyaci.options.child_class('fvSubnet')
    opt['query-target'].should.equal('children')
    opt['target-subtree-class'].should.equal('fvSubnet')


def testOrderBy():
    opt = pyaci.options.order_by('fvSubnet.addr')
    opt['order-by'].should.equal('fvSubnet.addr')


def testPage():
    opt = pyaci.options.page(1) & pyaci.options.page_size(50)
    opt['page'].should.equal(1)
    opt['page-size'].should.equal(50)


def testFilter():
    opt = pyaci.options.filter(pyaci.filters.Eq('fvTenant.name', 'cisco'))
    opt['query-target-filter'].should.equal('eq(fvTenant.name,"cisco")')


def testRspSubtreeInclude():
    opt = pyaci.options.rsp_subtree_include('relations')
    opt['rsp-subtree-include'].should.equal('relations')


def testRspSubtreeClass():
    opt = pyaci.options.rsp_subtree_class('fvAEPg')
    opt['rsp-subtree'].should.equal('full')
    opt['rsp-subtree-class'].should.equal('fvAEPg')


def testRspPropInclude():
    opt = pyaci.options.rsp_prop_include('config-only')
    opt['rsp-prop-include'].should.equal('config-only')


def testRspSubtreeChildren():
    opt = pyaci.options.rsp_subtree_children
    opt['rsp-subtree'].should.equal('children')


def testRspSubtreeFull():
    opt = pyaci.options.rsp_subtree_full
    opt['rsp-subtree'].should.equal('full')


def testSubtreeFilter():
    opt = pyaci.options.subtree_filter(pyaci.filters.Eq('fvTenant.name', 'cisco'))
    opt['rsp-subtree-filter'].should.equal('eq(fvTenant.name,"cisco")')
