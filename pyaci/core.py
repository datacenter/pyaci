# Copyright (c) 2014, 2015 Cisco Systems, Inc. All rights reserved.

"""
pyaci.core
~~~~~~~~~~~~~~~~~~~

This module contains the core classes of PyACI.
"""

from OpenSSL.crypto import FILETYPE_PEM, load_privatekey, sign
from collections import OrderedDict, defaultdict, deque
from lxml import etree
from requests import Request
from threading import Event
from io import BytesIO
from functools import reduce
from six import iteritems, iterkeys, itervalues
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
import xmltodict
import sys
import time
try:
    from urllib.parse import unquote, urlparse
except ImportError:
    from urllib import unquote
    from urlparse import urlparse

from .errors import (
    MetaError, MoError, ResourceError, RestError, UserError
)
from .utils import splitIntoRns
from . import options


logger = logging.getLogger(__name__)
payloadFormat = 'xml'
DELTA = 5 # time delta to allow for any variations of clock...

# Web Socket Statuses
WS_OPENING = 'Websocket Opening.'
WS_OPENED  = 'Websocket Opened.'
WS_ERRORED = 'Websocket Errored.'
WS_CLOSED  = 'Websocket Closed.'

def subLogger(name):
    return logging.getLogger('{}.{}'.format(__name__, name))


def _elementToString(e):
    return etree.tostring(e, pretty_print=True, encoding='unicode')


# TODO (2015-05-07, Praveen Kumar): Research a way to automatically
# load this by discovering the version from the node.

aciMetaDir = os.path.expanduser(os.environ.get('ACI_META_DIR', '~/.aci-meta'))

if not os.path.exists(aciMetaDir):
    aciClassMetas = dict()
else:
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
            for key, value in iteritems(kwargs):
                options += (key + '=' + value + '&')
            options = options[:-1]
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
        # never use certificate for subscription requests
        if "subscription" not in kwargs:
            self._x509Prep(rootApi, prepped, data)
        send_kwargs = rootApi._session.merge_environment_settings(
            prepped.url, proxies={},stream=None, verify=rootApi._verify, cert=None)
        response = rootApi._session.send(
            prepped, timeout=rootApi._timeout, **send_kwargs)

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
        if sys.version_info[0] >= 3:
            signature = signature.decode('ascii')

        cookie = ('APIC-Request-Signature={}; '
                  'APIC-Certificate-Algorithm=v1.0; '
                  'APIC-Certificate-Fingerprint=fingerprint; '
                  'APIC-Certificate-DN={}').format(
                      signature, rootApi._x509Dn)
        req.headers['Cookie'] = cookie

    def _rootApi(self):
        return self._parentApi._rootApi()


class Node(Api):
    def __init__(self, url, session=None, verify=False, disableWarnings=True,
                 timeout=None, aciMetaFilePath=None):
        super(Node, self).__init__()
        self._url = url
        if session is not None:
            self._session = session
        else:
            self._session = requests.session()

        if aciMetaFilePath is not None:
            with open(aciMetaFilePath, 'rb') as f:
                logger.debug('Loading meta information from %s',
                             aciMetaFilePath)
                aciMetaContents = json.load(f)
                self._aciClassMetas = aciMetaContents['classes']
        else:
            if not aciClassMetas:
                raise MetaError('ACI meta was not specified !')
            else:
                self._aciClassMetas = aciClassMetas

        self._timeout = timeout
        self._verify = verify
        if disableWarnings:
            requests.packages.urllib3.disable_warnings()
        self._apiUrlComponent = 'api'
        self._x509Key = None
        self._wsMos = defaultdict(deque)
        self._wsReady = Event()
        self._wsEvents = {}
        self._autoRefresh = False
        self._autoRefreshThread = None
        self._login = {}

    @property
    def session(self):
        return self._session

    @property
    def webSocketUrl(self):
        if 'APIC-cookie' in self._rootApi()._session.cookies:
            token = self._rootApi()._session.cookies['APIC-cookie']
        else:
            raise Exception('APIC-cookie NOT found.. Make sure you have logged in.')
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
        self._wsStatus = WS_OPENING
        self._wsError  = None
        self._wsReady.wait()
        if self._wsStatus != WS_OPENED:
            if self._wsError is not None:
                raise Exception(self._wsError)
            raise Exception('Error occurred when opening Websocket')

    def _handleWsOpen(self):
        logger.info('Opened WebSocket connection')
        self._wsStatus = WS_OPENED
        self._wsReady.set()
        self._wsLastRefresh = int(time.time())

    def _handleWsMessage(self, message):
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

    def _handleWsError(self, error):
        logger.error('Encountered WebSocket error: %s', error)
        self._wsStatus = WS_ERRORED
        self._wsError = error
        self._wsReady.set()

    def _handleWsClose(self):
        logger.info('Closed WebSocket connection')
        self._wsStatus = WS_CLOSED
        self._wsReady.set()

    def waitForWsMo(self, subscriptionId, timeout=None):
        logger.info('Waiting for the WebSocket MOs')
        if subscriptionId not in self._wsEvents:
            self._wsEvents[subscriptionId] = Event()
        return self._wsEvents[subscriptionId].wait(timeout)

    def hasWsMo(self, subscriptionId):
        return len(self._wsMos[subscriptionId]) > 0

    def popWsMo(self, subscriptionId):
        mo = self._wsMos[subscriptionId].popleft()
        if not self.hasWsMo(subscriptionId):
            self._wsEvents[subscriptionId].clear()
        return mo

    @property
    def mit(self):
        return Mo(self, 'topRoot', self._aciClassMetas)

    @property
    def methods(self):
        return MethodApi(self)

    @property
    def _relativeUrl(self):
        return self._url + '/' + self._apiUrlComponent

    def _rootApi(self):
        return self

    def _stopArThread(self):
        if self._autoRefresh and self._autoRefreshThread is not None:
            self._autoRefreshThread.stop()
            self._autoRefreshThread = None
            self._autoRefresh = False


class MoIter(Api):
    def __init__(self, parentApi, className, objects, aciClassMetas):
        self._parentApi = parentApi
        self._className = className
        self._objects = objects
        self._aciClassMetas = aciClassMetas
        self._aciClassMeta = aciClassMetas[self._className]
        self._rnFormat = self._aciClassMeta['rnFormat']
        self._iter = itervalues(self._objects)

    def __call__(self, *args, **kwargs):
        identifiedBy = self._aciClassMeta['identifiedBy']
        if (len(args) >= 1):
            if len(args) != len(identifiedBy):
                raise MoError(
                    'Class `{}` requires {} naming properties, '
                    'but only {} were provided'.format(
                        self._className, len(identifiedBy), len(args)
                    )
                )
            identifierDict = dict(zip(identifiedBy, args))
        else:
            for name in identifiedBy:
                if name not in kwargs:
                    raise MoError(
                        'Missing naming property `{}` for class `{}`'.format(
                            name, self._className
                        ))
            identifierDict = kwargs

        rn = self._rnFormat.format(**identifierDict)
        mo = self._parentApi._getChildByRn(rn)

        if mo is None:
            if self._parentApi.TopRoot._readOnlyTree:
                raise MoError(
                    'Mo with DN {} does not contain a child with RN {}'
                    .format(self._parentApi.Dn, rn))

            mo = Mo(self._parentApi, self._className, self._aciClassMetas)
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
    def __init__(self, parentApi, className, aciClassMetas):
        super(Mo, self).__init__(parentApi=parentApi)

        self._className = className
        self._aciClassMetas = aciClassMetas
        self._aciClassMeta = aciClassMetas[self._className]
        self._properties = {
            x[0]: None
            for x in self._aciClassMeta['properties'].items()
        }
        self._rnFormat = self._aciClassMeta['rnFormat']

        self._children = OrderedDict()
        self._childrenByClass = defaultdict(OrderedDict)
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
            if result.Parent is None:
                raise MoError('Reached topRoot after {} levels'.format(i))
            result = result.Parent
        return result

    @property
    def Children(self):
        return itervalues(self._children)

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

        return _elementToString(element(self))

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

        return _elementToString(
            element(self, elementPredicate, propertyPredicate))

    @Xml.setter
    def Xml(self, value):
        xml = bytes(bytearray(value, encoding='utf-8'))
        self._fromXmlElement(etree.fromstring(xml))

    def ParseXmlResponse(self, xml, localOnly=False, subscriptionIds=[]):
        # https://gist.github.com/karlcow/3258330
        xml = bytes(bytearray(xml, encoding='utf-8'))
        context = etree.iterparse(BytesIO(xml),
                                  events=('end',), tag='imdata')
        mos = []
        event, root = next(context)
        sIds = root.get('subscriptionId', '')
        if sIds:
            subscriptionIds.extend([str(x) for x in sIds.split(',')])
        for element in root.iterchildren():
            if 'dn' not in element.attrib:
                raise MoError('Property `dn` not found in element {}'.format(
                    _elementToString(element)))
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
        sIds = response.get('subscriptionId', [])
        if sIds:
            subscriptionIds.extend(sIds)
        mos = []
        for element in response['imdata']:
            name, value = next(iteritems(element))
            if 'dn' not in value['attributes']:
                raise MoError('Property `dn` not found in dict {}'.format(
                    value['attributes']))
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
            className = next(iterkeys(cdict))
            attributes = next(itervalues(cdict)).get('attributes', {})
            child = self._spawnChildFromAttributes(className, **attributes)
            child._fromObjectDict(cdict)

    def _fromXmlElement(self, element, localOnly=False):
        if element.tag != self._className:
            raise MoError(
                'Root element tag `{}` does not match with class `{}`'
                .format(element.tag, self._className))

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
            return MoIter(self, name, self._childrenByClass[name],
                          aciClassMetas=self._aciClassMetas)

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
        rnFormat = self._aciClassMetas[className]['rnFormat']
        rn = rnFormat.format(**attributes)
        return self._spawnChildFromRn(className, rn)


class AutoRefreshThread(threading.Thread):
    REFRESH_BEFORE = 60  # approx - this many seconds before expiry, do token refresh
    CHECK_INTERVAL = 10  # how long to sleep before waking to check for any work to do
    WS_REFRESH_INT = 40  # approx - this many seconds before subscription refresh

    def __init__(self, rootApi):
        super(AutoRefreshThread, self).__init__()
        self._stop_event = threading.Event()
        self._rootApi = rootApi

    def stop(self):
        self._stop_event.set()

    def isStopped(self):
        return self._stop_event.is_set()

    def _refreshLoginIfNeeded(self):
        now = int(time.time())
        if now + self.REFRESH_BEFORE > self._rootApi._login['nextRefreshBefore']:
            logger.debug('arThread: Need to refresh Token')
            refObj = self._rootApi.methods.LoginRefresh()
            resp = refObj.GET()
            # Process refresh response
            if payloadFormat != 'xml' or resp.text[:5] != '<?xml':
                logger.error('XML format of aaaLogin is only supported now')
                return
            doc = xmltodict.parse(resp.text)
            if 'imdata' in doc:
                if 'aaaLogin' in doc['imdata']:
                    root = self._rootApi
                    root._login = {}
                    lastLogin = int(time.time())
                    root._login['lastLoginTime'] = lastLogin
                    root._login['nextRefreshBefore'] = lastLogin - DELTA + \
                                                           int(doc['imdata']['aaaLogin']['@refreshTimeoutSeconds'])
                else:
                    logger.error('arThread: response for aaaRefresh does not have required aaaLogin Tag')
            else:
                logger.error('arThread: response for aaaRefresh does not have required imdata Tag')
        return

    def _refreshSubscriptionsIfNeeded(self):
        now = int(time.time())
        if len(self._rootApi._wsEvents) > 0 and \
           now >= self._rootApi._wsLastRefresh + self.WS_REFRESH_INT:
            ids=''
            for k in self._rootApi._wsEvents:
                ids+=k+','
            ids = ids[:-1]
            logger.debug('Refreshing Ids: %s', ids)
            wsRefreshObj = self._rootApi.methods.RefreshSubscriptions(ids)
            resp = wsRefreshObj.GET()
            if resp.status_code != requests.codes.ok:
                logger.error('Subscription Refresh Failed !!' + resp.text)
            else:
                self._rootApi._wsLastRefresh = now
        return

    def run(self):
        logger.debug('arThread: Starting up')
        while True:
            time.sleep(self.CHECK_INTERVAL)
            if self.isStopped():
                break
            self._refreshLoginIfNeeded()
            self._refreshSubscriptionsIfNeeded()
        logger.debug('arThread: Terminating')


class LoginMethod(Api):
    def __init__(self, parentApi):
        super(LoginMethod, self).__init__(parentApi=parentApi)
        self._moClassName = 'aaaUser'
        self._properties = {}

    def POST(self, format=None, **kwargs):
        resp = super(LoginMethod, self).POST(format=format, **kwargs)

        if resp is None or resp.status_code != requests.codes.ok:
            logger.debug('Login failed!')
            return resp

        if payloadFormat != 'xml' or resp.text[:5] != '<?xml':
            logger.error('XML format of aaaLogin is only supported now')
            return resp

        doc = xmltodict.parse(resp.text)
        if 'imdata' in doc:
            if 'aaaLogin' in doc['imdata']:
                root = self._rootApi()
                root._login = {}
                root._login['version'] = doc['imdata']['aaaLogin']['@version']
                root._login['userName'] = doc['imdata']['aaaLogin']['@userName']
                lastLogin = int(time.time())
                root._login['lastLoginTime'] = lastLogin
                root._login['nextRefreshBefore'] = lastLogin - DELTA + \
                                                               int(doc['imdata']['aaaLogin']['@refreshTimeoutSeconds'])
                logger.debug(root._login)
                if root._autoRefresh:
                    arThread = AutoRefreshThread(root)
                    root._autoRefreshThread = arThread
                    arThread.daemon = True
                    arThread.start()
        return resp

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

        return _elementToString(result)

    @property
    def _relativeUrl(self):
        return 'aaaLogin'

    def __call__(self, name, password=None, passwordFile=None, autoRefresh=False):
        if password is None and passwordFile is None:
            password = getpass.getpass('Enter {} password: '.format(name))
        elif password is None:
            with open(passwordFile, 'r') as f:
                password = f.read()
        self._properties['name'] = name
        self._properties['pwd'] = password
        rootApi = self._rootApi()
        rootApi._autoRefresh = autoRefresh
        return self


class AppLoginMethod(Api):
    def __init__(self, parentApi):
        super(AppLoginMethod, self).__init__(parentApi=parentApi)
        self._moClassName = "aaaAppToken"
        self._properties = {}

    def POST(self, format=None, **kwargs):
        resp = super(AppLoginMethod, self).POST(format=format, **kwargs)

        if resp is None or resp.status_code != requests.codes.ok:
            logger.debug('Login failed!')
            return resp

        if payloadFormat != 'xml' or resp.text[:5] != '<?xml':
            logger.error('XML format of AppLogin is only supported now')
            return resp

        # NOTE (2021-02-03, Praveen Kumar): /api/requestAppToken.xml doesn't set
        # the token in the cookies automatically. Hence, intercept the response
        # and set the cookie explicitly.
        doc = xmltodict.parse(resp.text)
        if 'imdata' in doc:
            if 'aaaLogin' in doc['imdata']:
                token = doc['imdata']['aaaLogin']['@token']
                domain = urlparse(resp.url).netloc.split(':')[0]
                self._rootApi().session.cookies.set(
                    'APIC-cookie', token, domain=domain
                )

        return resp

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

        return _elementToString(result)

    @property
    def _relativeUrl(self):
        return 'requestAppToken'

    def __call__(self, appName):
        self._properties['appName'] = appName
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

    def __call__(self):
        return self


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

        return _elementToString(result)

    @property
    def _relativeUrl(self):
        return 'changeSelfX509Cert'

    def __call__(self, userName, certName, certFile):
        self._properties['userName'] = userName
        self._properties['name'] = certName
        with open(certFile, 'r') as f:
            self._properties['data'] = f.read()
        return self


class LogoutMethod(Api):
    def __init__(self, parentApi):
        super(LogoutMethod, self).__init__(parentApi=parentApi)
        self._moClassName = 'aaaUser'
        self._properties = {}

    def POST(self, format=None, **kwargs):
        resp = super(LogoutMethod, self).POST(format=format, **kwargs)
        if resp.status_code == requests.codes.ok:
            self._rootApi()._stopArThread()

        return resp

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

        return _elementToString(result)

    @property
    def _relativeUrl(self):
        return 'aaaLogout'

    def __call__(self, user=None):
        root = self._rootApi()
        if user is None:
            self._properties['name'] = root._login['userName']
        else:
            self._properties['name'] = user
        return self


class RefreshSubscriptionsMethod(Api):
    def __init__(self, parentApi):
        super(RefreshSubscriptionsMethod, self).__init__(parentApi=parentApi)

    def GET(self, format=None, **kwargs):
        resp = None
        for sid in self._ids.split(','):
            args = {'id': sid}
            args.update(kwargs)
            resp = super(RefreshSubscriptionsMethod, self).GET(format=format, **args)
            if resp.status_code != requests.codes.ok:
                logger.error('Refresh of subscription id %s failed with status code: %d', sid, resp.status_code)
            # Current Subscription Refresh does one id at a time, so
            # we have to loop here - once it supports multiple ids, then
            # give the entire set of ids
        return resp

    @property
    def Json(self):
        return ''

    @property
    def Xml(self):
        return ''

    @property
    def _relativeUrl(self):
        return 'subscriptionRefresh'

    def __call__(self, ids):
        ''' ids are comma separate subscription ids '''
        self._ids = ids
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
        if format != 'xml':
            raise UserError('Unsupported format: {}'.format(format))
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
    def AppLogin(self):
        return AppLoginMethod(parentApi=self)

    @property
    def LoginRefresh(self):
        return LoginRefreshMethod(parentApi=self)

    @property
    def Logout(self):
        return LogoutMethod(parentApi=self)

    @property
    def RefreshSubscriptions(self):
        return RefreshSubscriptionsMethod(parentApi=self)

    @property
    def ChangeCert(self):
        return ChangeCertMethod(parentApi=self)

    @property
    def UploadPackage(self):
        return UploadPackageMethod(parentApi=self)

    @property
    def ResolveClass(self):
        return ResolveClassMethod(parentApi=self)
