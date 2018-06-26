#!/usr/bin/env python

import httpretty

import os
import logging
#pylint: disable=unused-import
import sure                     # flake8: noqa
import sys
import unittest

paths = [
    '..',
]
for path in paths:
    sys.path.append(os.path.abspath(path))

from pyaci.utils import (
    getParentDn, splitIntoRns, readOnlyTree, distributeConfig, mergeRoot)
from pyaci import Node

logging.captureWarnings(True)

class GetParentTests(unittest.TestCase):
    @staticmethod
    def testEmptyDn():
        getParentDn('').should.equal('')

    @staticmethod
    def testNoNamedTopLevel():
        getParentDn('uni').should.equal('')

    @staticmethod
    def testNoNamedSecondLevel():
        getParentDn('uni/infra').should.equal('uni')

    @staticmethod
    def testNoNamedThirdLevel():
        getParentDn('uni/infra/funcprof').should.equal('uni/infra')

    @staticmethod
    def testNamedThirdLevel():
        getParentDn('uni/tn-common/BD-lab').should.equal('uni/tn-common')

    @staticmethod
    def testNestedDn():
        (getParentDn('uni/epp/fv-[uni/tn-infra/ap-access/epg-default]').
         should.equal('uni/epp'))


class SplitIntoRnsTests(unittest.TestCase):
    @staticmethod
    def testEmptyDn():
        splitIntoRns('').should.equal([])

    @staticmethod
    def testNoNamedTopLevel():
        splitIntoRns('uni').should.equal(['uni'])

    @staticmethod
    def testNoNamedSecondLevel():
        splitIntoRns('uni/infra').should.equal(['uni', 'infra'])

    @staticmethod
    def testNestedDn():
        (splitIntoRns('uni/epp/fv-[uni/tn-infra/ap-access/epg-default]').
         should.equal(['uni', 'epp',
                       'fv-[uni/tn-infra/ap-access/epg-default]']))

def testReadOnlyTree():
    n = Node('')
    tree = n.mit
    #pylint: disable=pointless-statement
    tree.ReadOnlyTree.should.be.false
    with readOnlyTree(tree) as r:
        #pylint: disable=pointless-statement
        tree.ReadOnlyTree.should.be.true
        #pylint: disable=pointless-statement
        r.ReadOnlyTree.should.be.true
    #pylint: disable=pointless-statement
    tree.ReadOnlyTree.should.be.false


def testDistributeConfig():
    n = Node('')
    mit = n.mit
    mit.polUni().fvTenant('cisco')
    mit.polUni().fvTenant('insieme')
    mits = distributeConfig(mit)
    mits.should.have.length_of(2)
    mits[0].ReadOnlyTree = True
    mits[0].polUni().fvTenant('cisco').name.should.equal('cisco')
    mits[1].ReadOnlyTree = True
    mits[1].polUni().fvTenant('insieme').name.should.equal('insieme')

def testMergeRoot():
    n = Node('')
    t1 = n.mit
    t1.polUni().fvTenant('cisco')
    t2 = n.mit
    t2.polUni().fvTenant('insieme')

    mit = n.mit
    mergeRoot(mit, t1)
    mergeRoot(mit, t2)
    mit.ReadOnlyTree = True
    mit.polUni().fvTenant('cisco').name.should.equal('cisco')
    mit.polUni().fvTenant('insieme').name.should.equal('insieme')
