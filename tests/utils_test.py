#!/usr/bin/env python

import logging
import os
import sys
import unittest

import httpretty

# pylint: disable=unused-import
import sure  # flake8: noqa

paths = [
    '..',
]
for path in paths:
    sys.path.append(os.path.abspath(path))

from pyaci import Node
from pyaci.utils import distribute_config, get_parent_dn, merge_root, read_only_tree, split_into_rns

logging.captureWarnings(True)


class GetParentTests(unittest.TestCase):
    @staticmethod
    def test_empty_dn():
        get_parent_dn('').should.equal('')

    @staticmethod
    def test_no_named_top_level():
        get_parent_dn('uni').should.equal('')

    @staticmethod
    def test_no_named_second_level():
        get_parent_dn('uni/infra').should.equal('uni')

    @staticmethod
    def test_no_named_third_level():
        get_parent_dn('uni/infra/funcprof').should.equal('uni/infra')

    @staticmethod
    def test_named_third_level():
        get_parent_dn('uni/tn-common/BD-lab').should.equal('uni/tn-common')

    @staticmethod
    def test_nested_dn():
        (get_parent_dn('uni/epp/fv-[uni/tn-infra/ap-access/epg-default]').should.equal('uni/epp'))


class SplitIntoRnsTests(unittest.TestCase):
    @staticmethod
    def test_empty_dn():
        split_into_rns('').should.equal([])

    @staticmethod
    def test_no_named_top_level():
        split_into_rns('uni').should.equal(['uni'])

    @staticmethod
    def test_no_named_second_level():
        split_into_rns('uni/infra').should.equal(['uni', 'infra'])

    @staticmethod
    def test_nested_dn():
        (
            split_into_rns('uni/epp/fv-[uni/tn-infra/ap-access/epg-default]').should.equal(
                ['uni', 'epp', 'fv-[uni/tn-infra/ap-access/epg-default]']
            )
        )


def test_read_only_tree():
    n = Node('')
    tree = n.mit
    # pylint: disable=pointless-statement
    tree.read_only_tree.should.be.false
    with read_only_tree(tree) as r:
        # pylint: disable=pointless-statement
        tree.read_only_tree.should.be.true
        # pylint: disable=pointless-statement
        r.read_only_tree.should.be.true
    # pylint: disable=pointless-statement
    tree.read_only_tree.should.be.false


def test_distribute_config():
    n = Node('')
    mit = n.mit
    mit.polUni().fvTenant('cisco')
    mit.polUni().fvTenant('insieme')
    mits = distribute_config(mit)
    mits.should.have.length_of(2)
    mits[0].read_only_tree = True
    mits[0].polUni().fvTenant('cisco').name.should.equal('cisco')
    mits[1].read_only_tree = True
    mits[1].polUni().fvTenant('insieme').name.should.equal('insieme')


def test_merge_root():
    n = Node('')
    t1 = n.mit
    t1.polUni().fvTenant('cisco')
    t2 = n.mit
    t2.polUni().fvTenant('insieme')

    mit = n.mit
    merge_root(mit, t1)
    merge_root(mit, t2)
    mit.ReadOnlyTree = True
    mit.polUni().fvTenant('cisco').name.should.equal('cisco')
    mit.polUni().fvTenant('insieme').name.should.equal('insieme')
