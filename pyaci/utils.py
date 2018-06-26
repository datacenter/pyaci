# Copyright (c) 2014 Cisco Systems, Inc. All rights reserved.

"""
pyaci.utils
~~~~~~~~~~~~~~~~~~~

This module contains PyACI utility functions.
"""

from contextlib import contextmanager
import logging
import tarfile
from functools import reduce

logger = logging.getLogger(__name__)


def getParentDn(dn):
    """Get the parent DN of the given DN string."""
    if dn == '':
        return dn

    position = len(dn)
    nestingLevel = 0
    for ch in reversed(dn):
        position -= 1
        if ch == '/' and nestingLevel == 0:
            break
        elif ch == ']':
            nestingLevel += 1
        elif ch == '[':
            nestingLevel -= 1

    return dn[:position]


def splitIntoRns(dn):
    """Split the given DN string to a list of RN strings."""
    if dn == '':
        return []

    position = 0
    nestingLevel = 0
    splitAt = []
    for ch in dn:
        if ch == '/' and nestingLevel == 0:
            splitAt.append(position)
        elif ch == '[':
            nestingLevel += 1
        elif ch == ']':
            nestingLevel -= 1
        position += 1

    splitAt.append(len(dn))

    def reductionF(acc, x):
        if not acc:
            return [(0, x)]
        else:
            return acc + [(acc[-1][1] + 1, x)]

    splittingPoints = reduce(reductionF, splitAt, [])
    return list(map(lambda point: dn[point[0]:point[1]], splittingPoints))


@contextmanager
def readOnlyTree(mo):
    """Make the given MO tree read-only.

    The MO tree (starting from topRoot) remains read-only until the
    enclosing with statement returns.

    """
    readOnlyTreeOldValue = mo.ReadOnlyTree
    mo.ReadOnlyTree = True
    try:
        yield mo
    finally:
        mo.ReadOnlyTree = readOnlyTreeOldValue


def digestConfigExport(path, topRoot, format='xml'):
    """Digest an APIC config export file into the given topRoot.

    :param path: path to the config export file.
    :param topRoot: topRoot MO.

    """
    with tarfile.open(path, 'r') as tar:
        for member in tar:
            logger.debug('Processing member %s', member.name)
            if member.isreg() and ((member.name.endswith('.xml') and
                                    format == 'xml') or
                                   (member.name.endswith('.json') and
                                    format == 'json')):
                logger.debug('Digesting file %s', member.name)
                f = tar.extractfile(member)
                if member.name.find('_idfile') != -1:
                    if format == 'xml':
                        topRoot.Xml = f.read()
                    elif format == 'json':
                        topRoot.Json = f.read()
                else:
                    if format == 'xml':
                        topRoot.polUni().Xml = f.read()
                    elif format == 'json':
                        topRoot.polUni().Json = f.read()


def distributeConfig(root, result=None):
    """Distribute configuration from the given root MO into multiple
    roots.

    In order for an MO tree to be posted to APIC in a single
    operation, all MOs in that tree should belong to the same
    shard. APIC will reject if any of the MOs is not in the same
    shard. This function splits the given tree to multiple subtrees,
    ensuring that all the MOs in the subtre belong to the same context
    root. One can later post the individual subtrees without worrying
    about the context root implications.

    :param root: MO at the top of the tree to be processed.
    :param result: optional list of subtrees to append the result to.

    """
    if result is None:
        result = []
    for child in root.Children:
        if child._aciClassMeta['isContextRoot']:
            topRoot = root.TopRoot
            newRoot = topRoot._parentApi.mit
            newChild = newRoot.FromDn(child.Dn)
            # TODO (2015-04-02, Praveen Kumar): Clone the tree in a
            # better way.
            newChild.Xml = child.Xml
            result.append(newRoot)
        else:
            distributeConfig(child, result)
    return result


def mergeRoot(accumulator, root):
    """Merge the given root MO into the given acculumulator."""
    # TODO (2015-04-02, Praveen Kumar): Copy the tree in a better way.
    accumulator.Xml = root.Xml
    return accumulator
