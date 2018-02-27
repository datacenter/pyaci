# Copyright (c) 2014, 2015 Cisco Systems, Inc. All rights reserved.

"""
pyaci.core
~~~~~~~~~~~~~~~~~~~

This module contains the core classes of PyACI.
"""

from OpenSSL.crypto import FILETYPE_PEM, load_privatekey, sign
from collections import defaultdict, deque
from lxml import etree
from requests import Request
from threading import Event
from io import StringIO
import base64
import getpass
import json
import logging
import operator
import os
import parse
import requests
import ssl
import threading
import websocket
try:
    from urllib.parse import unquote
except ImportError:
    from urllib import unquote

from .errors import (
    MetaError, MoError, ResourceError, RestError, UserError
)
from .utils import splitIntoRns
from . import options


logger = logging.getLogger(__name__)
payloadFormat = 'xml'


def subLogger(name):
    return logging.getLogger('{}.{}'.format(__name__, name))


# TODO (2015-05-07, Praveen Kumar): Research a way to automatically
# load this by discovering the version from the node.

aciMetaDir = os.path.expanduser(os.environ.get('ACI_META_DIR', '~/.aci-meta'))

if not os.path.exists(aciMetaDir):
    raise MetaError('Unable to find ACI meta directory {}'.format(aciMetaDir))

aciMetaFile = os.path.join(aciMetaDir, 'aci-meta.json')

if not os.path.exists(aciMetaFile):
    raise MetaError('Unable to find ACI meta file {}'.format(aciMetaFile))

with open(aciMetaFile, 'rb') as f:
    logger.debug('Loading meta information from %s', aciMetaFile)
    aciMeta = json.load(f)
    aciClassMetas = aciMeta['classes']


class Api(object):
    def __init__(self, parentApi=None):
        self._parentApi = parentApi

    def GET(self, format=None, **kwargs):
        return self._performRequest('GET', format=format, **kwargs)

    def DELETE(self, format=None):
        return self._performRequest('DELETE', format=format)

    def POST(self, format=None, **kwargs):
        return self._performRequest(
            'POST', format=format, needData=True, **kwargs)

    def _url(self, format=None, **kwargs):
        if format is None:
            format = payloadFormat

        def loop(entity, accumulator):
            if entity is None:
                return accumulator
            else:
                if accumulator:
                    relativeUrl = entity._relativeUrl
                    if relativeUrl:
                        passDown = entity._relativeUrl + '/' + accumulator
                    else:
                        passDown = accumulator
                else:
                    passDown = entity._relativeUrl
                return loop(entity._parentApi, passDown)

        if kwargs:
            options = '?'
            for key, value in kwargs.items():
                options += (key + '=' + value + '&')
        else:
            options = ''

        return loop(self, '') + '.' + format + options

    def _performRequest(self, method, format=None, needData=False, **kwargs):
        if format is None:
            format = payloadFormat

        logger = subLogger(method)
        rootApi = self._rootApi()
        url = self._url(format, **kwargs)

        if needData:
            if format == 'json':
                data = self.Json
            elif format == 'xml':
                data = self.Xml
        else:
            data = None

        logger.debug('-> %s %s', method, url)
        if needData:
            logger.debug('%s', data)

        req = Request(method, url, data=data)
        prepped = rootApi._session.prepare_request(req)
        self._x509Prep(rootApi, prepped, data)
        response = rootApi._session.send(prepped, verify=rootApi._verify, timeout=rootApi._timeout)

        logger.debug('<- %d', response.status_code)
        logger.debug('%s', response.text)
        if response.status_code != requests.codes.ok:
            # TODO: Parse error message and extract fields.
            raise RestError(response.text)
        return response

    def _x509Prep(self, rootApi, req, data):
        if rootApi._x509Key is None:
            return
        payload = '{}{}'.format(req.method, req.url.replace(rootApi._url, ''))
        payload = unquote(payload)
        if data is not None:
            payload += data
        signature = base64.b64encode(sign(rootApi._x509Key, payload,
                                          'sha256'))
        cookie = ('APIC-Request-Signature={}; '
                  'APIC-Certificate-Algorithm=v1.0; '
                  'APIC-Certificate-Fingerprint=fingerprint; '
                  'APIC-Certificate-DN={}').format(
                      signature, rootApi._x509Dn)
        req.headers['Cookie'] = cookie

    def _rootApi(self):
        return self._parentApi._rootApi()


class Node(Api):
    def __init__(self, url, session=None, verify=False, disableWarnings=True, timeout=None):
        super(Node, self).__init__()
        self._url = url
        if session is not None:
            self._session = session
        else:
            self._session = requests.session()
        self._timeout = timeout
        self._verify = verify
        if disableWarnings:
            requests.packages.urllib3.disable_warnings()
        self._apiUrlComponent = 'api'
        self._x509Key = None
        self._wsMos = defaultdict(deque)
        self._wsReady = Event()
        self._wsEvents = {}

    @property
    def session(self):
        return self._session

    @property
    def webSocketUrl(self):
        token = self._rootApi()._session.cookies['APIC-cookie']
        return '{}/socket{}'.format(
            self._url.replace('https', 'wss').replace('http', 'ws'), token)

    def useX509CertAuth(self, userName, certName, keyFile, appcenter=False):
        with open(keyFile, 'r') as f:
            key = f.read()
        if appcenter:
            self._x509Dn = (self.mit.polUni().aaaUserEp().
                            aaaAppUser(userName).aaaUserCert(certName).Dn)
        else:
            self._x509Dn = (self.mit.polUni().aaaUserEp().
                            aaaUser(userName).aaaUserCert(certName).Dn)
        self._x509Key = load_privatekey(FILETYPE_PEM, key)

    def toggleTestApi(self, shouldEnable, dme='policymgr'):
        if shouldEnable:
            self._apiUrlComponent = 'testapi/{}'.format(dme)
        else:
            self._apiUrlComponent = 'api'

    def toggleDebugApi(self, shouldEnable, dme='policymgr'):
        if shouldEnable:
            self._apiUrlComponent = 'debugapi/{}'.format(dme)
        else:
            self._apiUrlComponent = 'api'

    def startWsListener(self):
        logger.info('Establishing WebSocket connection to %s',
                    self.webSocketUrl)
        ws = websocket.WebSocketApp(
            self.webSocketUrl,
            on_open=self._handleWsOpen,
            on_message=self._handleWsMessage,
            on_error=self._handleWsError,
            on_close=self._handleWsClose)
        wst = threading.Thread(target=lambda: ws.run_forever(
            sslopt={"cert_reqs": ssl.CERT_NONE}))
        wst.daemon = True
        wst.start()
        logger.info('Waiting for the WebSocket connection to open')
        self._wsReady.wait()

    def _handleWsOpen(self, ws):
        logger.info('Opened WebSocket connection')
        self._wsReady.set()

    def _handleWsMessage(self, ws, message):
        logger.debug('Got a message on WebSocket: %s', message)
        subscriptionIds = []
        if message[:5] == '<?xml':
            mos = self.mit.ParseXmlResponse(
                message, subscriptionIds=subscriptionIds)
        else:
            mos = self.mit.ParseJsonResponse(
                message, subscriptionIds=subscriptionIds)
        for subscriptionId in subscriptionIds:
            for mo in mos:
                self._wsMos[subscriptionId].append(mo)
            if subscriptionId not in self._wsEvents:
                self._wsEvents[subscriptionId] = Event()
            if mos:
                self._wsEvents[subscriptionId].set()

    def _handleWsError(self, ws, error):
        logger.error('Encountered WebSocket error: %s', error)
        self._wsReady.clear()

    def _handleWsClose(self, ws):
        logger.info('Closed WebSocket connection')
        self._wsReady.clear()

    def waitForWsMo(self, subscriptionId):
        logger.info('Waiting for the WebSocket MOs')
        if subscriptionId not in self._wsEvents:
            self._wsEvents[subscriptionId] = Event()
        self._wsEvents[subscriptionId].wait()

    def hasWsMo(self, subscriptionId):
        return len(self._wsMos[subscriptionId]) > 0

    def popWsMo(self, subscriptionId):
        mo = self._wsMos[subscriptionId].popleft()
        if not self.hasWsMo(subscriptionId):
            self._wsEvents[subscriptionId].clear()
        return mo

    @property
    def mit(self):
        return Mo(self, 'topRoot')

    @property
    def methods(self):
        return MethodApi(self)

    @property
    def _relativeUrl(self):
        return self._url + '/' + self._apiUrlComponent

    def _rootApi(self):
        return self


class MoIter(Api):
    def __init__(self, parentApi, className, objects):
        self._parentApi = parentApi
        self._className = className
        assert isinstance(objects, dict)
        self._objects = objects
        self._aciClassMeta = aciClassMetas[self._className]
        self._rnFormat = self._aciClassMeta['rnFormat']
        self._iter = self._objects.values()

    def __call__(self, *args, **kwargs):
        identifiedBy = self._aciClassMeta['identifiedBy']
        if (len(args) >= 1):
            assert len(args) == len(identifiedBy)
            identifierDict = dict(zip(identifiedBy, args))
        else:
            for name in identifiedBy:
                assert name in kwargs
            identifierDict = kwargs

        rn = self._rnFormat.format(**identifierDict)
        mo = self._parentApi._getChildByRn(rn)

        if mo is None:
            if self._parentApi.TopRoot._readOnlyTree:
                raise MoError(
                    'Mo with DN {} does not contain a child with RN {}'
                    .format(self._parentApi.Dn, rn))

            mo = Mo(self._parentApi, self._className)
            for name in identifiedBy:
                setattr(mo, name, identifierDict[name])
            self._parentApi._addChild(self._className, rn, mo)
            self._objects[rn] = mo

        for attribute in set(kwargs) - set(identifiedBy):
            setattr(mo, attribute, kwargs[attribute])

        return mo

    def __iter__(self):
        return self._iter

    def next(self):
        return next(self._iter)

    def __len__(self):
        return len(self._objects)


class Mo(Api):
    def __init__(self, parentApi, className):
        super(Mo, self).__init__(parentApi=parentApi)

        self._className = className
        self._aciClassMeta = aciClassMetas[self._className]
        self._properties = {
            x[0]: None
            for x in self._aciClassMeta['properties'].items()
        }
        self._rnFormat = self._aciClassMeta['rnFormat']

        self._children = {}
        self._childrenByClass = defaultdict(dict)
        self._readOnlyTree = False

    def FromDn(self, dn):
        def reductionF(acc, rn):
            dashAt = rn.find('-')
            rnPrefix = rn if dashAt == -1 else rn[:dashAt] + '-'
            className = acc._aciClassMeta['rnMap'][rnPrefix]
            return acc._spawnChildFromRn(className, rn)

        return reduce(reductionF, splitIntoRns(dn), self)

    @property
    def TopRoot(self):
        if self._isTopRoot():
            return self
        else:
            return self._parentApi.TopRoot

    @property
    def ReadOnlyTree(self):
        return self.TopRoot._readOnlyTree

    @ReadOnlyTree.setter
    def ReadOnlyTree(self, value):
        self.TopRoot._readOnlyTree = value

    @property
    def ClassName(self):
        return self._className

    @property
    def Rn(self):
        idDict = {
            k: v
            for k, v in self._properties.items()
            if k in self._aciClassMeta['identifiedBy']
        }
        return self._rnFormat.format(**idDict)

    @property
    def Dn(self):
        if self._parentApi._isTopRoot():
            return self.Rn
        else:
            return self._parentApi.Dn + '/' + self.Rn

    @property
    def Parent(self):
        if isinstance(self._parentApi, Mo):
            return self._parentApi
        else:
            return None

    def Up(self, level=1):
        result = self
        for i in range(level):
            result = result.Parent
            assert result is not None
        return result

    @property
    def Children(self):
        return self._children.values()

    @property
    def Status(self):
        return self._properties['status']

    @Status.setter
    def Status(self, value):
        self._properties['status'] = value

    @property
    def PropertyNames(self):
        return sorted(self._properties.keys())

    @property
    def NonEmptyPropertyNames(self):
        return sorted([k for k, v in self._properties.items()
                       if v is not None])

    @property
    def IsConfigurable(self):
        return self._aciClassMeta['isConfigurable']

    def IsConfigurableProperty(self, name):
        return (name in self._aciClassMeta['properties'] and
                self._aciClassMeta['properties'][name]['isConfigurable'])

    @property
    def Json(self):
        return json.dumps(self._dataDict(),
                          sort_keys=True, indent=2, separators=(',', ': '))

    @Json.setter
    def Json(self, value):
        self._fromObjectDict(json.loads(value))

    @property
    def Xml(self):
        def element(mo):
            result = etree.Element(mo._className)

            for key, value in mo._properties.items():
                if value is not None:
                    result.set(key, value)

            for child in mo._children.values():
                result.append(element(child))

            return result

        return etree.tostring(element(self), pretty_print=True)

    def GetXml(self, elementPredicate=lambda mo: True,
               propertyPredicate=lambda mo, name: True):
        def element(mo, elementPredicate, propertyPredicate):
            if not elementPredicate(mo):
                return None

            result = etree.Element(mo._className)

            for key, value in mo._properties.items():
                if value is not None:
                    if propertyPredicate(mo, key):
                        result.set(key, value)

            for child in mo._children.values():
                childElement = element(child, elementPredicate,
                                       propertyPredicate)
                if childElement is not None:
                    result.append(childElement)

            return result

        return etree.tostring(element(self, elementPredicate,
                                      propertyPredicate),
                              pretty_print=True)

    @Xml.setter
    def Xml(self, value):
        xml = bytes(bytearray(value, encoding='utf-8'))
        self._fromXmlElement(etree.fromstring(xml))

    def ParseXmlResponse(self, xml, localOnly=False, subscriptionIds=[]):
        # https://gist.github.com/karlcow/3258330
        xml = bytes(bytearray(xml, encoding='utf-8'))
        context = etree.iterparse(StringIO.StringIO(xml),
                                  events=('end',), tag='imdata')
        mos = []
        event, root = next(context)
        sIds = root.get('subscriptionId', '')
        if sIds:
            subscriptionIds.extend([str(x) for x in sIds.split(',')])
        for element in root.iterchildren():
            assert 'dn' in element.attrib
            if element.tag == 'moCount':
                mo = self.moCount()
            else:
                mo = self.FromDn(element.attrib['dn'])
            mo._fromXmlElement(element, localOnly=localOnly)
            element.clear()
            mos.append(mo)
        return mos

    def ParseJsonResponse(self, text, subscriptionIds=[]):
        response = json.loads(text)
        assert 'imdata' in response
        sIds = response.get('subscriptionId', [])
        if sIds:
            subscriptionIds.extend(sIds)
        mos = []
        for element in response['imdata']:
            name, value = element.items().next()
            assert 'dn' in value['attributes']
            mo = self.FromDn(value['attributes']['dn'])
            mo._fromObjectDict(element)
            mos.append(mo)
        return mos

    def GET(self, format=None, **kwargs):
        if format is None:
            format = payloadFormat

        topRoot = self.TopRoot

        subscriptionIds = []
        response = super(Mo, self).GET(format, **kwargs)
        if format == 'json':
            result = topRoot.ParseJsonResponse(response.text,
                                               subscriptionIds=subscriptionIds)
        elif format == 'xml':
            result = topRoot.ParseXmlResponse(response.text,
                                              subscriptionIds=subscriptionIds)

        topRoot.ReadOnlyTree = True
        if subscriptionIds:
            return result, subscriptionIds[0]
        else:
            return result

    @property
    def _relativeUrl(self):
        if self._className == 'topRoot':
            return 'mo'
        else:
            return self.Rn

    def _fromObjectDict(self, objectDict):
        attributes = objectDict[self._className].get('attributes', {})

        for key, value in attributes.items():
            self._properties[key] = value

        children = objectDict[self._className].get('children', [])
        for cdict in children:
            className = cdict.keys().next()
            attributes = cdict.values().next().get('attributes', {})
            child = self._spawnChildFromAttributes(className, **attributes)
            child._fromObjectDict(cdict)

    def _fromXmlElement(self, element, localOnly=False):
        assert element.tag == self._className

        if localOnly and element.attrib.get('lcOwn', 'local') != 'local':
            return

        for key, value in element.attrib.items():
            self._properties[key] = value

        for celement in element.iterchildren('*'):
            className = celement.tag
            attributes = celement.attrib
            child = self._spawnChildFromAttributes(className, **attributes)
            child._fromXmlElement(celement, localOnly=localOnly)

    def _dataDict(self):
        data = {}
        objectData = {}
        data[self._className] = objectData

        attributes = {
            k: v
            for k, v in self._properties.items()
            if v is not None
        }
        if attributes:
            objectData['attributes'] = attributes

        if self._children:
            objectData['children'] = []

        for child in self._children.values():
            objectData['children'].append(child._dataDict())

        return data

    def __getattr__(self, name):
        if name in self._properties:
            return self._properties[name]

        if name in self._aciClassMeta['contains']:
            return MoIter(self, name, self._childrenByClass[name])

        raise AttributeError('{} is not a valid attribute for class {}'.
                             format(name, self.ClassName))

    def __setattr__(self, name, value):
        if '_properties' in self.__dict__ and name in self._properties:
            self._properties[name] = value
        else:
            super(Mo, self).__setattr__(name, value)

    def _isTopRoot(self):
        return self._className == 'topRoot'

    def _getChildByRn(self, rn):
        return self._children.get(rn, None)

    def _addChild(self, className, rn, child):
        self._children[rn] = child
        self._childrenByClass[className][rn] = child

    def _spawnChildFromRn(self, className, rn):
        # TODO: Refactor.
        moIter = getattr(self, className)
        parsed = parse.parse(moIter._rnFormat, rn)
        if parsed is None:
            logging.debug('RN parsing failed, RN: {}, format: {}'.
                          format(rn, moIter._rnFormat))
            # FIXME (2015-04-08, Praveen Kumar): Hack alert!
            rn = rn.replace('[]', '[None]')
            if rn.endswith('-'):
                rn = rn + 'None'
            parsed = parse.parse(moIter._rnFormat, rn)
        identifierDict = parsed.named
        orderedIdentifiers = [
            t[0] for t in sorted(parsed.spans.items(),
                                 key=operator.itemgetter(1))
        ]
        identifierArgs = [
            identifierDict[name] for name in orderedIdentifiers
        ]
        return moIter(*identifierArgs)

    def _spawnChildFromAttributes(self, className, **attributes):
        rnFormat = aciClassMetas[className]['rnFormat']
        rn = rnFormat.format(**attributes)
        return self._spawnChildFromRn(className, rn)


class LoginMethod(Api):
    def __init__(self, parentApi):
        super(LoginMethod, self).__init__(parentApi=parentApi)
        self._moClassName = 'aaaUser'
        self._properties = {}

    @property
    def Json(self):
        result = {}
        result[self._moClassName] = {'attributes': self._properties.copy()}
        return json.dumps(result,
                          sort_keys=True, indent=2, separators=(',', ': '))

    @property
    def Xml(self):
        result = etree.Element(self._moClassName)

        for key, value in self._properties.items():
            result.set(key, value)

        return etree.tostring(result, pretty_print=True)

    @property
    def _relativeUrl(self):
        return 'aaaLogin'

    def __call__(self, name, password=None, passwordFile=None):
        if password is None and passwordFile is None:
            password = getpass.getpass('Enter {} password: '.format(name))
        elif password is None:
            with open(passwordFile, 'r') as f:
                password = f.read()
        self._properties['name'] = name
        self._properties['pwd'] = password
        return self


class LoginRefreshMethod(Api):
    def __init__(self, parentApi):
        super(LoginRefreshMethod, self).__init__(parentApi=parentApi)
        self._moClassName = 'aaaRefresh'

    @property
    def Json(self):
        return ''

    @property
    def Xml(self):
        return ''

    @property
    def _relativeUrl(self):
        return 'aaaRefresh'


class ChangeCertMethod(Api):
    def __init__(self, parentApi):
        super(ChangeCertMethod, self).__init__(parentApi=parentApi)
        self._moClassName = 'aaaChangeX509Cert'
        self._properties = {}

    @property
    def Json(self):
        result = {}
        result[self._moClassName] = {'attributes': self._properties.copy()}
        return json.dumps(result,
                          sort_keys=True, indent=2, separators=(',', ': '))

    @property
    def Xml(self):
        result = etree.Element(self._moClassName)

        for key, value in self._properties.items():
            result.set(key, value)

        return etree.tostring(result, pretty_print=True)

    @property
    def _relativeUrl(self):
        return 'changeSelfX509Cert'

    def __call__(self, userName, certName, certFile):
        self._properties['userName'] = userName
        self._properties['name'] = certName
        with open(certFile, 'r') as f:
            self._properties['data'] = f.read()
        return self


class UploadPackageMethod(Api):
    def __init__(self, parentApi):
        super(UploadPackageMethod, self).__init__(parentApi=parentApi)
        self._packageFile = None

    @property
    def _relativeUrl(self):
        return 'ppi/node/mo'

    def __call__(self, packageFile):
        self._packageFile = packageFile
        return self

    def POST(self, format='xml'):
        # TODO (2015-05-23, Praveen Kumar): Fix this method to work
        # with certificate based authentication.
        root = self._rootApi()
        assert format == 'xml'
        if not os.path.exists(self._packageFile):
            raise ResourceError('File not found: ' + self.packageFile)
        with open(self._packageFile, 'r') as f:
            response = root._session.request(
                'POST', self._url(format), files={'file': f},
                verify=root._verify
            )
        if response.status_code != requests.codes.ok:
            # TODO: Parse error message and extract fields.
            raise RestError(response.text)
        return response


class ResolveClassMethod(Api):
    def __init__(self, parentApi):
        super(ResolveClassMethod, self).__init__(parentApi=parentApi)

    @property
    def _relativeUrl(self):
        return 'class/' + self._className

    def __call__(self, className):
        self._className = className
        return self

    def GET(self, format=None, mit=None, autoPage=False, pageSize=10000,
            **kwargs):
        if format is None:
            format = payloadFormat

        subscriptionIds = []
        topRoot = self._rootApi().mit if mit is None else mit
        if autoPage:
            # TODO: Subscription is not supported with autoPage option.
            if 'subscription' in kwargs:
                raise UserError(
                    'Subscription is not suppored with autoPage option')
            logger.debug('Auto paginating query with page size of %d',
                         pageSize)
            currentPage = 0
            results = []
            while True:
                pageOptions = (options.pageSize(str(pageSize)) &
                               options.page(str(currentPage)))
                newKwargs = dict(pageOptions.items() + kwargs.items())
                logger.debug('Querying page %d', currentPage)
                response = super(ResolveClassMethod, self).GET(format,
                                                               **newKwargs)
                if format == 'json':
                    result = topRoot.ParseJsonResponse(response.text)
                elif format == 'xml':
                    result = topRoot.ParseXmlResponse(response.text)
                logger.debug('Got %s objects', len(result))
                results.append(result)
                if len(result) < pageSize:
                    break
                currentPage += 1
            result = [mo for resultList in results for mo in resultList]
        else:
            response = super(ResolveClassMethod, self).GET(format, **kwargs)
            if format == 'json':
                result = topRoot.ParseJsonResponse(
                    response.text, subscriptionIds=subscriptionIds)
            elif format == 'xml':
                result = topRoot.ParseXmlResponse(
                    response.text, subscriptionIds=subscriptionIds)

        topRoot.ReadOnlyTree = True

        if subscriptionIds:
            return result, subscriptionIds[0]
        else:
            return result


class MethodApi(Api):
    def __init__(self, parentApi):
        super(MethodApi, self).__init__(parentApi=parentApi)

    @property
    def _relativeUrl(self):
        return ''

    @property
    def Login(self):
        return LoginMethod(parentApi=self)

    @property
    def LoginRefresh(self):
        return LoginRefreshMethod(parentApi=self)

    @property
    def ChangeCert(self):
        return ChangeCertMethod(parentApi=self)

    @property
    def UploadPackage(self):
        return UploadPackageMethod(parentApi=self)

    @property
    def ResolveClass(self):
        return ResolveClassMethod(parentApi=self)
