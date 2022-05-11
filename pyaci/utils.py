# Copyright (c) 2014 Cisco Systems, Inc. All rights reserved.

"""
pyaci.utils
~~~~~~~~~~~~~~~~~~~

This module contains PyACI utility functions.
"""

import logging
import tarfile
from contextlib import contextmanager
from functools import reduce

logger = logging.getLogger(__name__)


def get_parent_dn(dn):
    """Get the parent DN of the given DN string."""
    if dn == '':
        return dn

    position = len(dn)
    nesting_level = 0
    for ch in reversed(dn):
        position -= 1
        if ch == '/' and nesting_level == 0:
            break
        elif ch == ']':
            nesting_level += 1
        elif ch == '[':
            nesting_level -= 1

    return dn[:position]


def split_into_rns(dn):
    """Split the given DN string to a list of RN strings."""
    if dn == '':
        return []

    position = 0
    nesting_level = 0
    split_at = []
    for ch in dn:
        if ch == '/' and nesting_level == 0:
            split_at.append(position)
        elif ch == '[':
            nesting_level += 1
        elif ch == ']':
            nesting_level -= 1
        position += 1

    split_at.append(len(dn))

    def reduction_f(acc, x):
        if not acc:
            return [(0, x)]
        else:
            return acc + [(acc[-1][1] + 1, x)]

    splitting_points = reduce(reduction_f, split_at, [])
    return list(map(lambda point: dn[point[0] : point[1]], splitting_points))


@contextmanager
def read_only_tree(mo):
    """Make the given MO tree read-only.

    The MO tree (starting from top_root) remains read-only until the
    enclosing with statement returns.

    """
    read_only_tree_old_value = mo.read_only_tree
    mo.read_only_tree = True
    try:
        yield mo
    finally:
        mo.read_only_tree = read_only_tree_old_value


def digest_config_export(path, top_root, format='xml'):
    """Digest an APIC config export file into the given top_root.

    :param path: path to the config export file.
    :param top_root: top_root MO.

    """
    with tarfile.open(path, 'r') as tar:
        for member in tar:
            logger.debug('Processing member %s', member.name)
            if member.isreg() and (
                (member.name.endswith('.xml') and format == 'xml')
                or (member.name.endswith('.json') and format == 'json')
            ):
                logger.debug('Digesting file %s', member.name)
                f = tar.extractfile(member)
                if member.name.find('_idfile') != -1:
                    if format == 'xml':
                        top_root.xml = f.read()
                    elif format == 'json':
                        top_root.json = f.read()
                else:
                    if format == 'xml':
                        top_root.polUni().xml = f.read()
                    elif format == 'json':
                        top_root.polUni().json = f.read()


def distribute_config(root, result=None):
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
    for child in root.children:
        if child._aci_class_meta['isContextRoot']:
            top_root = root.top_root
            new_root = top_root._parent_api.mit
            new_child = new_root.from_dn(child.dn)
            # TODO (2015-04-02, Praveen Kumar): Clone the tree in a
            # better way.
            new_child.xml = child.xml
            result.append(new_root)
        else:
            distribute_config(child, result)
    return result


def merge_root(accumulator, root):
    """Merge the given root MO into the given acculumulator."""
    # TODO (2015-04-02, Praveen Kumar): Copy the tree in a better way.
    accumulator.xml = root.xml
    return accumulator
