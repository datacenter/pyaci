#!/usr/bin/env python

import copy
import os
import json


def main():
    aciMetaDir = os.path.expanduser(os.environ.get('ACI_META_DIR',
                                                   '~/.aci-meta'))
    aciMetaFile = os.path.join(aciMetaDir, 'aci-meta.json')
    with open(aciMetaFile, 'rb') as f:
        aciMeta = json.load(f)
        aciClassMetas = aciMeta['classes']

    limitedClasses = {
        'topRoot', 'polUni', 'fvTenant', 'fvCtx', 'fvBD', 'fvRsCtx',
        'fvAp', 'fvAEPg', 'fvRsBd', 'fvEpPCont', 'fvEpP'
    }
    limitedClassMetas = {}
    for className in aciClassMetas:
        if className not in limitedClasses:
            continue

        limitedClassMetas[className] = copy.deepcopy(aciClassMetas[className])

        limitedClassMetas[className]['contains'] = {}
        for key, value in aciClassMetas[className]['contains'].iteritems():
            if key in limitedClasses:
                limitedClassMetas[className]['contains'][key] = value

        limitedClassMetas[className]['rnMap'] = {}
        for key, value in aciClassMetas[className]['rnMap'].iteritems():
            if value in limitedClasses:
                limitedClassMetas[className]['rnMap'][key] = value

    limitedMeta = {}
    limitedMeta['classes'] = limitedClassMetas

    with open('aci-meta.json', 'wb') as out:
        json.dump(limitedMeta, out,
                  sort_keys=True, indent=2, separators=(',', ': '))

if __name__ == '__main__':
    main()
