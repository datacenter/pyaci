#!/usr/bin/env python

import httpretty

import os
import sure                     # flake8: noqa
import sys
import textwrap
import unittest

paths = [
    '..',
]
for path in paths:
    sys.path.append(os.path.abspath(path))

from pyaci.utils import getParentDn, splitIntoRns


class GetParentTests(unittest.TestCase):
    def testEmptyDn(self):
        getParentDn('').should.equal('')

    def testNoNamedTopLevel(self):
        getParentDn('uni').should.equal('')

    def testNoNamedSecondLevel(self):
        getParentDn('uni/infra').should.equal('uni')

    def testNoNamedThirdLevel(self):
        getParentDn('uni/infra/funcprof').should.equal('uni/infra')

    def testNamedThirdLevel(self):
        getParentDn('uni/tn-common/BD-lab').should.equal('uni/tn-common')

    def testNestedDn(self):
        (getParentDn('uni/epp/fv-[uni/tn-infra/ap-access/epg-default]').
         should.equal('uni/epp'))


class SplitIntoRnsTests(unittest.TestCase):
    def testEmptyDn(self):
        splitIntoRns('').should.equal([])

    def testNoNamedTopLevel(self):
        splitIntoRns('uni').should.equal(['uni'])

    def testNoNamedSecondLevel(self):
        splitIntoRns('uni/infra').should.equal(['uni', 'infra'])

    def testNestedDn(self):
        (splitIntoRns('uni/epp/fv-[uni/tn-infra/ap-access/epg-default]').
         should.equal(['uni', 'epp',
                       'fv-[uni/tn-infra/ap-access/epg-default]']))
