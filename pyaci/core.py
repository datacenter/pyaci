"""
pyaci.core
~~~~~~~~~~~~~~~~~~~

This module contains the core classes of PyACI.
"""

import base64
import getpass
import json as json_module
import logging
import operator
import os
import ssl
import sys
import threading
import time
from collections import OrderedDict, defaultdict, deque
from functools import reduce
from io import BytesIO
from threading import Event

import parse
import requests
import websocket
import xmltodict
from lxml import etree
from OpenSSL.crypto import FILETYPE_PEM, load_privatekey, sign
from requests import Request
from six.moves.urllib.parse import unquote, urlparse

from . import options
from .errors import MetaError, MoError, ResourceError, RestError, UserError
from .utils import split_into_rns

logger = logging.getLogger(__name__)
payload_format = 'xml'
DELTA = 5  # time delta to allow for any variations of clock...

# Web Socket Statuses
WS_OPENING = 'Websocket Opening.'
WS_OPENED = 'Websocket Opened.'
WS_ERRORED = 'Websocket Errored.'
WS_CLOSED = 'Websocket Closed.'


def sub_logger(name):
    return logging.getLogger(f'{__name__}.{name}')


def _element_to_string(e):
    return etree.tostring(e, pretty_print=True, encoding='unicode')


# TODO: Jonas - Dynamic fetch
aciMetaDir = os.path.expanduser(os.environ.get('ACI_META_DIR', '~/.aci-meta'))


aciMetaFile = os.path.join(aciMetaDir, 'aci-meta.json')
if os.path.exists(aciMetaFile):
    with open(aciMetaFile, 'rb') as f:
        logger.debug('Loading meta information from %s', aciMetaFile)
        aciMeta = json_module.load(f)
        aci_class_metas = aciMeta['classes']
else:
    aci_class_metas = dict()


class Api:
    def __init__(self, parent_api=None, user_proxies=None):
        self._parent_api = parent_api
        self._user_proxies = user_proxies

    def get(self, format=None, **kwargs):
        return self._perform_request('get', format=format, **kwargs)

    def delete(self, format=None):
        return self._perform_request('delete', format=format)

    def post(self, format=None, **kwargs):
        return self._perform_request('post', format=format, need_data=True, **kwargs)

    def _url(self, format=None, **kwargs):
        if format is None:
            format = payload_format

        def loop(entity, accumulator):
            if entity is None:
                return accumulator
            else:
                if accumulator:
                    relative_url = entity._relative_url
                    if relative_url:
                        pass_down = entity._relative_url + '/' + accumulator
                    else:
                        pass_down = accumulator
                else:
                    pass_down = entity._relative_url
                return loop(entity._parent_api, pass_down)

        if kwargs:
            options = '?'
            for key, value in kwargs.items():
                options += key + '=' + value + '&'
            options = options[:-1]
        else:
            options = ''

        return loop(self, '') + '.' + format + options

    def _perform_request(self, method, format=None, need_data=False, **kwargs):
        if format is None:
            format = payload_format
        logger = sub_logger(method)
        root_api = self._root_api()
        url = self._url(format, **kwargs)

        if need_data:
            if format == 'json':
                data = self.json
            elif format == 'xml':
                data = self.xml
        else:
            data = None

        logger.debug('-> %s %s', method, url)
        if need_data:
            logger.debug('%s', data)

        req = Request(method.upper(), url, data=data)
        prepped = root_api._session.prepare_request(req)
        # never use certificate for subscription requests
        if 'subscription' not in kwargs:
            self._x509Prep(root_api, prepped, data)
        send_kwargs = root_api._session.merge_environment_settings(
            prepped.url, proxies={}, stream=None, verify=root_api._verify, cert=None
        )

        if root_api._user_proxies is not None:
            send_kwargs['proxies'] = root_api._user_proxies
        response = root_api._session.send(prepped, timeout=root_api._timeout, **send_kwargs)

        logger.debug('<- %d', response.status_code)
        logger.debug('%s', response.text)
        if response.status_code != requests.codes.ok:
            # TODO: Parse error message and extract fields.
            raise RestError(response.text)
        return response

    def _x509Prep(self, root_api, req, data):
        if root_api._x509Key is None:
            return
        payload = '{}{}'.format(req.method, req.url.replace(root_api._url, ''))
        payload = unquote(payload)
        if data is not None:
            payload += data
        signature = base64.b64encode(sign(root_api._x509Key, payload, 'sha256'))
        if sys.version_info[0] >= 3:
            signature = signature.decode('ascii')

        cookie = (
            'APIC-Request-Signature={}; '
            'APIC-Certificate-Algorithm=v1.0; '
            'APIC-Certificate-Fingerprint=fingerprint; '
            'APIC-Certificate-DN={}'
        ).format(signature, root_api._x509Dn)
        req.headers['Cookie'] = cookie

    def _root_api(self):
        return self._parent_api._root_api()


class Node(Api):
    def __init__(
        self,
        url,
        session=None,
        verify=False,
        disable_arnings=True,
        timeout=None,
        aci_meta_file_path=None,
        user_proxies=None,
    ):
        super().__init__(user_proxies=user_proxies)
        self._url = url
        if session is not None:
            self._session = session
        else:
            self._session = requests.session()

        if aci_meta_file_path is not None:
            with open(aci_meta_file_path, 'rb') as f:
                logger.debug('Loading meta information from %s', aci_meta_file_path)
                aci_meta_contents = json_module.load(f)
                self._aci_class_metas = aci_meta_contents['classes']
        else:
            if not aci_class_metas:
                raise MetaError('ACI meta was not specified !')
            else:
                self._aci_class_metas = aci_class_metas

        self._timeout = timeout
        self._verify = verify
        if disable_arnings:
            requests.packages.urllib3.disable_warnings()
        self._api_url_component = 'api'
        self._x509Key = None
        self._ws_mos = defaultdict(deque)
        self._ws_ready = Event()
        self._ws_events = {}
        self._auto_refresh = False
        self._auto_refresh_thread = None
        self._login = {}

    @property
    def session(self):
        return self._session

    @property
    def web_socket_url(self):
        if 'APIC-cookie' in self._root_api()._session.cookies:
            token = self._root_api()._session.cookies['APIC-cookie']
        else:
            raise Exception('APIC-cookie NOT found.. Make sure you have logged in.')
        return '{}/socket{}'.format(self._url.replace('https', 'wss').replace('http', 'ws'), token)

    def useX509CertAuth(self, userName, certName, keyFile, appcenter=False):
        with open(keyFile) as f:
            key = f.read()
        if appcenter:
            self._x509Dn = self.mit.polUni().aaaUserEp().aaaAppUser(userName).aaaUserCert(certName).dn
        else:
            self._x509Dn = self.mit.polUni().aaaUserEp().aaaUser(userName).aaaUserCert(certName).dn
        self._x509Key = load_privatekey(FILETYPE_PEM, key)

    def toggle_test_api(self, should_enable, dme='policymgr'):
        if should_enable:
            self._api_url_component = f'testapi/{dme}'
        else:
            self._api_url_component = 'api'

    def toggle_debug_api(self, should_enable, dme='policymgr'):
        if should_enable:
            self._api_url_component = f'debugapi/{dme}'
        else:
            self._api_url_component = 'api'

    def start_ws_listener(self):
        logger.info('Establishing WebSocket connection to %s', self.web_socket_url)
        ws = websocket.WebSocketApp(
            self.web_socket_url,
            on_open=self._handle_ws_open,
            on_message=self._handle_ws_message,
            on_error=self._handle_ws_error,
            on_close=self._handle_ws_close,
        )

        run_forever_kwargs = {'sslopt': {'cert_reqs': ssl.CERT_NONE}}
        logger.info(f'URL {self.web_socket_url} user_proxy {self._user_proxies}')
        if self._user_proxies:
            try:
                proxyUrl = self._user_proxies.get('https', self._user_proxies.get('http', None))
                if proxyUrl:
                    run_forever_kwargs['http_proxy_host'] = urlparse(proxyUrl).netloc.split(':')[0]
                    run_forever_kwargs['http_proxy_port'] = int(urlparse(proxyUrl).netloc.split(':')[1])
                    run_forever_kwargs['proxy_type'] = 'http'
            except ValueError:
                logger.info(f'http(s) proxy unavailable for {self.web_socket_url}')
        wst = threading.Thread(target=lambda: ws.run_forever(**run_forever_kwargs))

        wst.daemon = True
        wst.start()
        logger.info('Waiting for the WebSocket connection to open')
        self._ws_status = WS_OPENING
        self._ws_error = None
        self._ws_ready.wait()
        if self._ws_status != WS_OPENED:
            if self._ws_error is not None:
                raise Exception(self._ws_error)
            raise Exception('Error occurred when opening Websocket')

    def _handle_ws_open(self):
        logger.info('Opened WebSocket connection')
        self._ws_status = WS_OPENED
        self._ws_ready.set()
        self._ws_last_refresh = int(time.time())

    def _handle_ws_message(self, message):
        logger.debug('Got a message on WebSocket: %s', message)
        subscription_ids = []
        if message[:5] == '<?xml':
            mos = self.mit.parse_xml_response(message, subscription_ids=subscription_ids)
        else:
            mos = self.mit.parse_json_response(message, subscription_ids=subscription_ids)
        for subscriptionId in subscription_ids:
            for mo in mos:
                self._ws_mos[subscriptionId].append(mo)
            if subscriptionId not in self._ws_events:
                self._ws_events[subscriptionId] = Event()
            if mos:
                self._ws_events[subscriptionId].set()

    def _handle_ws_error(self, error):
        logger.error('Encountered WebSocket error: %s', error)
        self._ws_status = WS_ERRORED
        self._ws_error = error
        self._ws_ready.set()

    def _handle_ws_close(self):
        logger.info('Closed WebSocket connection')
        self._ws_status = WS_CLOSED
        self._ws_ready.set()

    def wait_for_ws_mo(self, subscriptionId, timeout=None):
        logger.info('Waiting for the WebSocket MOs')
        if subscriptionId not in self._ws_events:
            self._ws_events[subscriptionId] = Event()
        return self._ws_events[subscriptionId].wait(timeout)

    def has_ws_mo(self, subscriptionId):
        return len(self._ws_mos[subscriptionId]) > 0

    def pop_ws_mo(self, subscriptionId):
        mo = self._ws_mos[subscriptionId].popleft()
        if not self.has_ws_mo(subscriptionId):
            self._ws_events[subscriptionId].clear()
        return mo

    @property
    def mit(self):
        return Mo(self, 'topRoot', self._aci_class_metas)

    @property
    def methods(self):
        return MethodApi(self)

    @property
    def _relative_url(self):
        return self._url + '/' + self._api_url_component

    def _root_api(self):
        return self

    def _stop_ar_thread(self):
        if self._auto_refresh and self._auto_refresh_thread is not None:
            self._auto_refresh_thread.stop()
            self._auto_refresh_thread = None
            self._auto_refresh = False


class MoIter(Api):
    def __init__(self, parent_api, class_name, objects, aci_class_metas):
        self._parent_api = parent_api
        self._class_name = class_name
        self._objects = objects
        self._aci_class_metas = aci_class_metas
        self._aci_class_meta = aci_class_metas[self._class_name]
        self._rn_format = self._aci_class_meta['rnFormat']
        self._iter = self._objects.values()

    def __call__(self, *args, **kwargs):
        identified_by = self._aci_class_meta['identifiedBy']
        if len(args) >= 1:
            if len(args) != len(identified_by):
                raise MoError(
                    'Class `{}` requires {} naming properties, '
                    'but only {} were provided'.format(self._class_name, len(identified_by), len(args))
                )
            identifier_dict = dict(zip(identified_by, args))
        else:
            for name in identified_by:
                if name not in kwargs:
                    raise MoError(f'Missing naming property `{name}` for class `{self._class_name}`')
            identifier_dict = kwargs

        rn = self._rn_format.format(**identifier_dict)
        mo = self._parent_api._get_child_by_rn(rn)

        if mo is None:
            if self._parent_api.top_root._read_only_tree:
                raise MoError(f'Mo with DN {self._parent_api.dn} does not contain a child with RN {rn}')

            mo = Mo(self._parent_api, self._class_name, self._aci_class_metas)
            for name in identified_by:
                setattr(mo, name, identifier_dict[name])
            self._parent_api._add_child(self._class_name, rn, mo)
            self._objects[rn] = mo

        for attribute in set(kwargs) - set(identified_by):
            setattr(mo, attribute, kwargs[attribute])

        return mo

    def __iter__(self):
        return self._iter

    def next(self):
        return next(self._iter)

    def __len__(self):
        return len(self._objects)


class Mo(Api):
    def __init__(self, parent_api, class_name, aci_class_metas):
        super().__init__(parent_api=parent_api)

        self._class_name = class_name
        self._aci_class_metas = aci_class_metas
        self._aci_class_meta = aci_class_metas[self._class_name]
        self._properties = {x[0]: None for x in self._aci_class_meta['properties'].items()}
        self._rn_format = self._aci_class_meta['rnFormat']

        self._children = OrderedDict()
        self._children_by_class = defaultdict(OrderedDict)
        self._read_only_tree = False

    def from_dn(self, dn):
        def reduction_f(acc, rn):
            dash_at = rn.find('-')
            rn_prefix = rn if dash_at == -1 else rn[:dash_at] + '-'
            class_name = acc._aci_class_meta['rnMap'][rn_prefix]
            return acc._spawn_child_from_rn(class_name, rn)

        return reduce(reduction_f, split_into_rns(dn), self)

    @property
    def top_root(self):
        if self._is_top_root():
            return self
        else:
            return self._parent_api.top_root

    @property
    def read_only_tree(self):
        return self.top_root._read_only_tree

    @read_only_tree.setter
    def read_only_tree(self, value):
        self.top_root._read_only_tree = value

    @property
    def class_name(self):
        return self._class_name

    @property
    def rn(self):
        id_dict = {k: v for k, v in self._properties.items() if k in self._aci_class_meta['identifiedBy']}
        return self._rn_format.format(**id_dict)

    @property
    def dn(self):
        if self._parent_api._is_top_root():
            return self.rn
        else:
            return self._parent_api.dn + '/' + self.rn

    @property
    def parent(self):
        if isinstance(self._parent_api, Mo):
            return self._parent_api
        else:
            return None

    def up(self, level=1):
        result = self
        for i in range(level):
            if result.parent is None:
                raise MoError(f'Reached top_root after {i} levels')
            result = result.parent
        return result

    @property
    def children(self):
        return self._children.values()

    @property
    def status(self):
        return self._properties['status']

    @status.setter
    def status(self, value):
        self._properties['status'] = value

    @property
    def property_names(self):
        return sorted(self._properties.keys())

    @property
    def non_empty_property_names(self):
        return sorted(k for k, v in self._properties.items() if v is not None)

    @property
    def is_configurable(self):
        return self._aci_class_meta['isConfigurable']

    def is_configurable_property(self, name):
        return name in self._aci_class_meta['properties'] and self._aci_class_meta['properties'][name]['isConfigurable']

    @property
    def json(self):
        return json_module.dumps(self._data_dict(), sort_keys=True, indent=2, separators=(',', ': '))

    @json.setter
    def json(self, value):
        self._from_object_dict(json_module.loads(value))

    @property
    def xml(self):
        def element(mo):
            result = etree.Element(mo._class_name)

            for key, value in mo._properties.items():
                if value is not None:
                    result.set(key, value)

            for child in mo._children.values():
                result.append(element(child))

            return result

        return _element_to_string(element(self))

    def get_xml(self, element_predicate=lambda mo: True, property_predicate=lambda mo, name: True):
        def element(mo, element_predicate, property_predicate):
            if not element_predicate(mo):
                return None

            result = etree.Element(mo._class_name)

            for key, value in mo._properties.items():
                if value is not None:
                    if property_predicate(mo, key):
                        result.set(key, value)

            for child in mo._children.values():
                child_element = element(child, element_predicate, property_predicate)
                if child_element is not None:
                    result.append(child_element)

            return result

        return _element_to_string(element(self, element_predicate, property_predicate))

    @xml.setter
    def xml(self, value):
        xml = bytes(bytearray(value, encoding='utf-8'))
        self._from_xml_element(etree.fromstring(xml))

    def parse_xml_response(self, xml, local_only=False, subscription_ids=[]):
        # https://gist.github.com/karlcow/3258330
        xml = bytes(bytearray(xml, encoding='utf-8'))
        context = etree.iterparse(BytesIO(xml), events=('end',), tag='imdata')
        mos = []
        event, root = next(context)
        sIds = root.get('subscriptionId', '')
        if sIds:
            subscription_ids.extend([str(x) for x in sIds.split(',')])
        for element in root.iterchildren():
            if 'dn' not in element.attrib:
                raise MoError(f'Property `dn` not found in element {_element_to_string(element)}')
            if element.tag == 'moCount':
                mo = self.moCount()
            else:
                mo = self.from_dn(element.attrib['dn'])
            mo._from_xml_element(element, local_only=local_only)
            element.clear()
            mos.append(mo)
        return mos

    def parse_json_response(self, text, subscription_ids=[]):
        response = json_module.loads(text)
        s_ids = response.get('subscriptionId', [])
        if s_ids:
            subscription_ids.extend(s_ids)
        mos = []
        for element in response['imdata']:
            name, value = next(iter(element.items()))
            if 'dn' not in value['attributes']:
                raise MoError('Property `dn` not found in dict {}'.format(value['attributes']))
            mo = self.from_dn(value['attributes']['dn'])
            mo._from_object_dict(element)
            mos.append(mo)
        return mos

    def get(self, format=None, **kwargs):
        if format is None:
            format = payload_format

        top_root = self.top_root

        subscription_ids = []
        response = super().get(format, **kwargs)
        if format == 'json':
            result = top_root.parse_json_response(response.text, subscription_ids=subscription_ids)
        elif format == 'xml':
            result = top_root.parse_xml_response(response.text, subscription_ids=subscription_ids)

        top_root.read_only_tree = True
        if subscription_ids:
            return result, subscription_ids[0]
        else:
            return result

    @property
    def _relative_url(self):
        if self._class_name == 'topRoot':
            return 'mo'
        else:
            return self.rn

    def _from_object_dict(self, object_dict):
        attributes = object_dict[self._class_name].get('attributes', {})

        for key, value in attributes.items():
            self._properties[key] = value

        children = object_dict[self._class_name].get('children', [])
        for cdict in children:
            class_name = next(iter(cdict.keys()))
            attributes = next(iter(cdict.values())).get('attributes', {})
            child = self._spawn_child_from_attributes(class_name, **attributes)
            child._from_object_dict(cdict)

    def _from_xml_element(self, element, local_only=False):
        if element.tag != self._class_name:
            raise MoError(f'Root element tag `{element.tag}` does not match with class `{self._class_name}`')

        if local_only and element.attrib.get('lcOwn', 'local') != 'local':
            return

        for key, value in element.attrib.items():
            self._properties[key] = value

        for celement in element.iterchildren('*'):
            class_name = celement.tag
            attributes = celement.attrib
            child = self._spawn_child_from_attributes(class_name, **attributes)
            child._from_xml_element(celement, local_only=local_only)

    def _data_dict(self):
        data = {}
        object_data = {}
        data[self._class_name] = object_data

        attributes = {k: v for k, v in self._properties.items() if v is not None}
        if attributes:
            object_data['attributes'] = attributes

        if self._children:
            object_data['children'] = []

        for child in self._children.values():
            object_data['children'].append(child._data_dict())

        return data

    def __getattr__(self, name):
        if name in self._properties:
            return self._properties[name]

        if name in self._aci_class_meta['contains']:
            return MoIter(
                self,
                name,
                self._children_by_class[name],
                aci_class_metas=self._aci_class_metas,
            )

        raise AttributeError(f'{name} is not a valid attribute for class {self.class_name}')

    def __setattr__(self, name, value):
        if '_properties' in self.__dict__ and name in self._properties:
            self._properties[name] = value
        else:
            super().__setattr__(name, value)

    def _is_top_root(self):
        return self._class_name == 'topRoot'

    def _get_child_by_rn(self, rn):
        return self._children.get(rn, None)

    def _add_child(self, class_name, rn, child):
        self._children[rn] = child
        self._children_by_class[class_name][rn] = child

    def _spawn_child_from_rn(self, class_name, rn):
        # TODO: Refactor.
        mo_iter = getattr(self, class_name)
        parsed = parse.parse(mo_iter._rn_format, rn)
        if parsed is None:
            logging.debug(f'RN parsing failed, RN: {rn}, format: {mo_iter._rn_format}')
            # FIXME (2015-04-08, Praveen Kumar): Hack alert!
            rn = rn.replace('[]', '[None]')
            if rn.endswith('-'):
                rn = f'{rn}None'
            parsed = parse.parse(mo_iter._rn_format, rn)
        identifier_dict = parsed.named
        ordered_identifiers = [t[0] for t in sorted(parsed.spans.items(), key=operator.itemgetter(1))]
        identifier_args = [identifier_dict[name] for name in ordered_identifiers]
        return mo_iter(*identifier_args)

    def _spawn_child_from_attributes(self, class_name, **attributes):
        rn_format = self._aci_class_metas[class_name]['rnFormat']
        rn = rn_format.format(**attributes)
        return self._spawn_child_from_rn(class_name, rn)


class AutoRefreshThread(threading.Thread):
    REFRESH_BEFORE = 60  # approx - this many seconds before expiry, do token refresh
    CHECK_INTERVAL = 10  # how long to sleep before waking to check for any work to do
    WS_REFRESH_INT = 40  # approx - this many seconds before subscription refresh

    def __init__(self, root_api):
        super().__init__()
        self._stop_event = threading.Event()
        self._root_api = root_api

    def stop(self):
        self._stop_event.set()

    def is_stopped(self):
        return self._stop_event.is_set()

    def _refresh_login_if_needed(self):
        now = int(time.time())
        if now + self.REFRESH_BEFORE > self._root_api._login['next_refresh_before']:
            logger.debug('ar_thread: Need to refresh Token')
            ref_obj = self._root_api.methods.login_refresh()
            resp = ref_obj.get()
            # Process refresh response
            if payload_format != 'xml' or resp.text[:5] != '<?xml':
                logger.error('XML format of aaaLogin is only supported now')
                return
            doc = xmltodict.parse(resp.text)
            if 'imdata' in doc:
                if 'aaaLogin' in doc['imdata']:
                    root = self._root_api
                    root._login = {}
                    last_login = int(time.time())
                    root._login['last_login_time'] = last_login
                    root._login['next_refresh_before'] = (
                        last_login - DELTA + int(doc['imdata']['aaaLogin']['@refreshTimeoutSeconds'])
                    )
                else:
                    logger.error('ar_thread: response for aaaRefresh does not have required aaaLogin Tag')
            else:
                logger.error('ar_thread: response for aaaRefresh does not have required imdata Tag')
        return

    def _refresh_subscriptions_if_needed(self):
        now = int(time.time())
        if len(self._root_api._ws_events) > 0 and now >= self._root_api._ws_last_refresh + self.WS_REFRESH_INT:
            ids = ''
            for k in self._root_api._ws_events:
                ids += k + ','
            ids = ids[:-1]
            logger.debug('Refreshing Ids: %s', ids)
            ws_refresh_obj = self._root_api.methods.refresh_subscriptions(ids)
            resp = ws_refresh_obj.get()
            if resp.status_code != requests.codes.ok:
                logger.error('Subscription Refresh Failed !!' + resp.text)
            else:
                self._root_api._ws_last_refresh = now
        return

    def run(self):
        logger.debug('ar_thread: Starting up')
        while True:
            time.sleep(self.CHECK_INTERVAL)
            if self.is_stopped():
                break
            self._refresh_login_if_needed()
            self._refresh_subscriptions_if_needed()
        logger.debug('ar_thread: Terminating')


class LoginMethod(Api):
    def __init__(self, parent_api):
        super().__init__(parent_api=parent_api)
        self._mo_class_name = 'aaaUser'
        self._properties = {}

    def post(self, format=None, **kwargs):
        resp = super().post(format=format, **kwargs)

        if resp is None or resp.status_code != requests.codes.ok:
            logger.debug('login failed!')
            return resp

        if payload_format != 'xml' or resp.text[:5] != '<?xml':
            logger.error('XML format of aaaLogin is only supported now')
            return resp

        doc = xmltodict.parse(resp.text)
        if 'imdata' in doc:
            if 'aaaLogin' in doc['imdata']:
                root = self._root_api()
                root._login = {}
                root._login['version'] = doc['imdata']['aaaLogin']['@version']
                root._login['user_name'] = doc['imdata']['aaaLogin']['@userName']
                lastLogin = int(time.time())
                root._login['last_login_time'] = lastLogin
                root._login['next_refresh_before'] = (
                    lastLogin - DELTA + int(doc['imdata']['aaaLogin']['@refreshTimeoutSeconds'])
                )
                logger.debug(root._login)
                if root._auto_refresh:
                    ar_thread = AutoRefreshThread(root)
                    root._auto_refresh_thread = ar_thread
                    ar_thread.daemon = True
                    ar_thread.start()
        return resp

    @property
    def json(self):
        result = {}
        result[self._mo_class_name] = {'attributes': self._properties.copy()}
        return json_module.dumps(result, sort_keys=True, indent=2, separators=(',', ': '))

    @property
    def xml(self):
        result = etree.Element(self._mo_class_name)

        for key, value in self._properties.items():
            result.set(key, value)

        return _element_to_string(result)

    @property
    def _relative_url(self):
        return 'aaaLogin'

    def __call__(self, name, password=None, password_file=None, auto_refresh=False):
        if password is None and password_file is None:
            password = getpass.getpass(f'Enter {name} password: ')
        elif password is None:
            with open(password_file) as f:
                password = f.read()
        self._properties['name'] = name
        self._properties['pwd'] = password
        root_api = self._root_api()
        root_api._auto_refresh = auto_refresh
        return self


class AppLoginMethod(Api):
    def __init__(self, parent_api):
        super().__init__(parent_api=parent_api)
        self._mo_class_name = 'aaaAppToken'
        self._properties = {}

    def post(self, format=None, **kwargs):
        resp = super().post(format=format, **kwargs)

        if resp is None or resp.status_code != requests.codes.ok:
            logger.debug('login failed!')
            return resp

        if payload_format != 'xml' or resp.text[:5] != '<?xml':
            logger.error('XML format of app_login is only supported now')
            return resp

        # NOTE (2021-02-03, Praveen Kumar): /api/requestAppToken.xml doesn't set
        # the token in the cookies automatically. Hence, intercept the response
        # and set the cookie explicitly.
        doc = xmltodict.parse(resp.text)
        if 'imdata' in doc:
            if 'aaaLogin' in doc['imdata']:
                token = doc['imdata']['aaaLogin']['@token']
                domain = urlparse(resp.url).netloc.split(':')[0]
                self._root_api().session.cookies.set('APIC-cookie', token, domain=domain)

        return resp

    @property
    def json(self):
        result = {}
        result[self._mo_class_name] = {'attributes': self._properties.copy()}
        return json_module.dumps(result, sort_keys=True, indent=2, separators=(',', ': '))

    @property
    def xml(self):
        result = etree.Element(self._mo_class_name)

        for key, value in self._properties.items():
            result.set(key, value)

        return _element_to_string(result)

    @property
    def _relative_url(self):
        return 'requestAppToken'

    def __call__(self, app_name):
        self._properties['appName'] = app_name
        return self


class LoginRefreshMethod(Api):
    def __init__(self, parent_api):
        super().__init__(parent_api=parent_api)
        self._mo_class_name = 'aaaRefresh'

    @property
    def json(self):
        return ''

    @property
    def xml(self):
        return ''

    @property
    def _relative_url(self):
        return 'aaaRefresh'

    def __call__(self):
        return self


class ChangeCertMethod(Api):
    def __init__(self, parent_api):
        super().__init__(parent_api=parent_api)
        self._mo_class_name = 'aaaChangeX509Cert'
        self._properties = {}

    @property
    def json(self):
        result = {}
        result[self._mo_class_name] = {'attributes': self._properties.copy()}
        return json_module.dumps(result, sort_keys=True, indent=2, separators=(',', ': '))

    @property
    def xml(self):
        result = etree.Element(self._mo_class_name)

        for key, value in self._properties.items():
            result.set(key, value)

        return _element_to_string(result)

    @property
    def _relative_url(self):
        return 'changeSelfX509Cert'

    def __call__(self, userName, certName, certFile):
        self._properties['userName'] = userName
        self._properties['name'] = certName
        with open(certFile) as f:
            self._properties['data'] = f.read()
        return self


class LogoutMethod(Api):
    def __init__(self, parent_api):
        super().__init__(parent_api=parent_api)
        self._mo_class_name = 'aaaUser'
        self._properties = {}

    def post(self, format=None, **kwargs):
        resp = super().post(format=format, **kwargs)
        if resp.status_code == requests.codes.ok:
            self._root_api()._stop_ar_thread()

        return resp

    @property
    def json(self):
        result = {}
        result[self._mo_class_name] = {'attributes': self._properties.copy()}
        return json_module.dumps(result, sort_keys=True, indent=2, separators=(',', ': '))

    @property
    def xml(self):
        result = etree.Element(self._mo_class_name)

        for key, value in self._properties.items():
            result.set(key, value)

        return _element_to_string(result)

    @property
    def _relative_url(self):
        return 'aaaLogout'

    def __call__(self, user=None):
        root = self._root_api()
        if user is None:
            self._properties['name'] = root._login['user_name']
        else:
            self._properties['name'] = user
        return self


class RefreshSubscriptionsMethod(Api):
    def __init__(self, parent_api):
        super().__init__(parent_api=parent_api)

    def get(self, format=None, **kwargs):
        resp = None
        for sid in self._ids.split(','):
            args = {'id': sid}
            args.update(kwargs)
            resp = super().get(format=format, **args)
            if resp.status_code != requests.codes.ok:
                logger.error(
                    'Refresh of subscription id %s failed with status code: %d',
                    sid,
                    resp.status_code,
                )
            # Current Subscription Refresh does one id at a time, so
            # we have to loop here - once it supports multiple ids, then
            # give the entire set of ids
        return resp

    @property
    def json(self):
        return ''

    @property
    def xml(self):
        return ''

    @property
    def _relative_url(self):
        return 'subscriptionRefresh'

    def __call__(self, ids):
        """ids are comma separate subscription ids"""
        self._ids = ids
        return self


class UploadPackageMethod(Api):
    def __init__(self, parent_api):
        super().__init__(parent_api=parent_api)
        self._package_file = None

    @property
    def _relative_url(self):
        return 'ppi/node/mo'

    def __call__(self, packageFile):
        self._package_file = packageFile
        return self

    def post(self, format='xml'):
        # TODO (2015-05-23, Praveen Kumar): Fix this method to work
        # with certificate based authentication.
        root = self._root_api()
        if format != 'xml':
            raise UserError(f'Unsupported format: {format}')
        if not os.path.exists(self._package_file):
            raise ResourceError('File not found: ' + self.package_file)
        with open(self._package_file) as f:
            response = root._session.request('post', self._url(format), files={'file': f}, verify=root._verify)
        if response.status_code != requests.codes.ok:
            # TODO: Parse error message and extract fields.
            raise RestError(response.text)
        return response


class ResolveClassMethod(Api):
    def __init__(self, parent_api):
        super().__init__(parent_api=parent_api)

    @property
    def _relative_url(self):
        return 'class/' + self._class_name

    def __call__(self, class_name):
        self._class_name = class_name
        return self

    def get(self, format=None, mit=None, auto_page=False, page_size=10000, **kwargs):
        if format is None:
            format = payload_format

        subscription_ids = []
        top_root = self._root_api().mit if mit is None else mit
        if auto_page:
            # TODO: Subscription is not supported with auto_page option.
            if 'subscription' in kwargs:
                raise UserError('Subscription is not suppored with auto_page option')
            logger.debug('Auto paginating query with page size of %d', page_size)
            current_page = 0
            results = []
            while True:
                page_options = options.page_size(str(page_size)) & options.page(str(current_page))
                new_kwargs = dict(page_options.items() + kwargs.items())
                logger.debug('Querying page %d', current_page)
                response = super().get(format, **new_kwargs)
                if format == 'json':
                    result = top_root.parse_json_response(response.text)
                elif format == 'xml':
                    result = top_root.parse_xml_response(response.text)
                logger.debug('Got %s objects', len(result))
                results.append(result)
                if len(result) < page_size:
                    break
                current_page += 1
            result = [mo for resultList in results for mo in resultList]
        else:
            response = super().get(format, **kwargs)
            if format == 'json':
                result = top_root.parse_json_response(response.text, subscription_ids=subscription_ids)
            elif format == 'xml':
                result = top_root.parse_xml_response(response.text, subscription_ids=subscription_ids)

        top_root.read_only_tree = True

        if subscription_ids:
            return result, subscription_ids[0]
        else:
            return result


class MethodApi(Api):
    def __init__(self, parent_api):
        super().__init__(parent_api=parent_api)

    @property
    def _relative_url(self):
        return ''

    @property
    def login(self):
        return LoginMethod(parent_api=self)

    @property
    def app_login(self):
        return AppLoginMethod(parent_api=self)

    @property
    def login_refresh(self):
        return LoginRefreshMethod(parent_api=self)

    @property
    def logout(self):
        return LogoutMethod(parent_api=self)

    @property
    def refresh_subscriptions(self):
        return RefreshSubscriptionsMethod(parent_api=self)

    @property
    def change_cert(self):
        return ChangeCertMethod(parent_api=self)

    @property
    def upload_package(self):
        return UploadPackageMethod(parent_api=self)

    @property
    def resolve_class(self):
        return ResolveClassMethod(parent_api=self)
