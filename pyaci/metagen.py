#!/usr/bin/env python

from insieme.pymit.pyaccess import PyClassDirectory
import json
import multiprocessing
import re

dir = PyClassDirectory()


def getPaciClassName(classMeta):
    return classMeta.getPkgName() + classMeta.getClassName()


def getRnPrefix(classMeta):
    rnFormat = classMeta.getRnFormat()
    dashAt = rnFormat.find('-')
    rnPrefix = rnFormat if dashAt == -1 else rnFormat[:dashAt]
    return rnPrefix


def generateClassMeta(className):
    classMeta = dir.lookup(className)
    paciClassName = classMeta.getPkgName() + classMeta.getClassName()
    paciClassMeta = {}

    paciClassMeta['isAbstract'] = not classMeta.isConcrete()
    paciClassMeta['isConfigurable'] = classMeta.isConfigurable()
    paciClassMeta['isContextRoot'] = classMeta.isContextRoot()

    paciClassMeta['identifiedBy'] = (
        [x for x in classMeta.getOrderedNamingProps()]
    )
    paciClassMeta['rnFormat'] = re.sub(r'(%\((\w+)\)s)',
                                       r'{\2}',
                                       classMeta.getRnFormat())
    paciClassMeta['properties'] = {
        p.getName(): {
            'isConfigurable': p.isConfig()
        }
        for p in classMeta.getProperties()
    }

    paciClassMeta['contains'] = {
        getPaciClassName(x): '' for x in classMeta.getContainedClasses()
    }

    paciClassMeta['rnMap'] = {
        getRnPrefix(x): getPaciClassName(x)
        for x in classMeta.getContainedClasses()
    }

    return (paciClassName, paciClassMeta)


def main():
    classNames = dir.getClassNames()

    # import itertools
    # classNames = itertools.islice(classNames, 0, 100)

    aciMeta = {}

    pool = multiprocessing.Pool(multiprocessing.cpu_count())
    aciClassMetas = pool.imap(generateClassMeta, classNames)
    aciMeta['classes'] = dict(aciClassMetas)

    with open('aci-meta.json', 'wb') as out:
        json.dump(aciMeta, out,
                  sort_keys=True, indent=2, separators=(',', ': '))

if __name__ == '__main__':
    main()
