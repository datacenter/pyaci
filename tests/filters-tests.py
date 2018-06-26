import logging
import os
#pylint: disable=unused-import
import sure                     # flake8: noqa
import sys

paths = [
    '..',
]
for path in paths:
    sys.path.append(os.path.abspath(path))

import pyaci

logging.captureWarnings(True)

def testUnary():
    nt = pyaci.filters.Not(pyaci.filters.Eq('fvATg.pcTag', 50))
    str(nt).should.equal('not(eq(fvATg.pcTag,50))')

def testBinary():
    matrix = {
        'Eq': 'eq',
        'Ne': 'ne',
        'Lt': 'lt',
        'Gt': 'gt',
        'Le': 'le',
        'Ge': 'ge',
    }
    for name, op in matrix.items():
        f = getattr(pyaci.filters, name)('fvATg.pcTag', 50)
        str(f).should.equal('{}(fvATg.pcTag,50)'.format(op))

def testTernary():
    bw = pyaci.filters.Bw('fvATg.pcTag', 5, 500)
    str(bw).should.equal('bw(fvATg.pcTag,"5","500")')

def testCombinations():
    f1 = pyaci.filters.Eq('fvATg.name', 'cisco')
    f2 = pyaci.filters.Eq('fvATg.pcTag', 50)

    str(~f1).should.equal('not(eq(fvATg.name,"cisco"))')
    str(f1 & f2).should.equal('and(eq(fvATg.name,"cisco"),eq(fvATg.pcTag,50))')
    str(f1 | f2).should.equal('or(eq(fvATg.name,"cisco"),eq(fvATg.pcTag,50))')
    str(f1 ^ f2).should.equal('xor(eq(fvATg.name,"cisco"),eq(fvATg.pcTag,50))')
