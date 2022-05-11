import logging
import os
import sys
import textwrap
import time
import unittest

import httpretty

# pylint: disable=unused-import
import sure  # flake8: noqa
from lxml import etree

paths = [
    '..',
]
for path in paths:
    sys.path.append(os.path.abspath(path))

import pyaci

logging.captureWarnings(True)

url = 'http://praveek6-bld.insieme.local:7000'


class MoTests(unittest.TestCase):
    def setUp(self):
        self.api = pyaci.Node(url)
        self.tree = self.api.mit

    def testPolUni(self):
        uni = self.tree.polUni()
        uni.rn.should.equal('uni')
        uni.dn.should.equal('uni')
        uni._url().should_not.be.different_of(url + '/api/mo/' + uni.dn + '.xml')

    def test_fv_tenant(self):
        tenant = self.tree.polUni().fvTenant('common')
        tenant.rn.should.equal('tn-common')
        tenant.dn.should.equal('uni/tn-common')
        tenant._url().should_not.be.different_of(url + '/api/mo/' + tenant.dn + '.xml')

    def testFvTenantOptionalArgs(self):
        tenant = self.tree.polUni().fvTenant('common', descr='Common tenant')
        tenant.dn.should.equal('uni/tn-common')
        tenant.descr.should.equal('Common tenant')

    def test_fv_tenant_from_keyword_arguments(self):
        tenant = self.tree.polUni().fvTenant(name='common', descr='Common tenant')
        tenant.dn.should.equal('uni/tn-common')
        tenant.descr.should.equal('Common tenant')

    def test_url(self):
        mos = self.api.mit
        mos._url().should.equal(url + '/api/mo.xml')

    def test_uni_from_dn(self):
        uni = self.api.mit.from_dn('uni')
        uni.should.be.an(pyaci.core.Mo)
        uni.class_name.should.equal('polUni')
        uni.dn.should.equal('uni')

    def test_tenant_from_dn(self):
        tenant = self.api.mit.from_dn('uni/tn-common')
        tenant.should.be.an(pyaci.core.Mo)
        tenant.class_name.should.equal('fvTenant')
        tenant.name.should.equal('common')
        tenant.dn.should.equal('uni/tn-common')

    def test_ep_from_dn(self):
        epp = self.api.mit.from_dn('uni/epp/fv-[uni/tn-infra/ap-access/epg-default]')
        epp.should.be.an(pyaci.core.Mo)
        epp.class_name.should.equal('fvEpP')
        epp.epgPKey.should.equal('uni/tn-infra/ap-access/epg-default')
        epp.dn.should.equal('uni/epp/fv-[uni/tn-infra/ap-access/epg-default]')

    def test_json(self):
        uni = self.tree.polUni()
        tenant = uni.fvTenant('mgmt')
        tenant.json.should_not.be.different_of(
            textwrap.dedent(
                """\
        {
          "fvTenant": {
            "attributes": {
              "name": "mgmt"
            }
          }
        }"""
            )
        )

        uni.json.should_not.be.different_of(
            textwrap.dedent(
                """\
        {
          "polUni": {
            "children": [
              {
                "fvTenant": {
                  "attributes": {
                    "name": "mgmt"
                  }
                }
              }
            ]
          }
        }"""
            )
        )

    def test_json_setter(self):
        tenant = self.tree.polUni().fvTenant('common')
        tenant.json = textwrap.dedent(
            """\
        {
          "fvTenant": {
            "attributes": {
              "name": "common",
              "descr": "Common tenant for sharing"
            }
          }
        }"""
        )
        tenant.name.should.equal('common')
        tenant.descr.should.equal('Common tenant for sharing')

    def test_json_setter_tree(self):
        tree = textwrap.dedent(
            """\
        {
          "polUni": {
            "children": [
              {
                "fvTenant": {
                  "attributes": {
                    "name": "test"
                  },
                  "children": [
                    {
                      "fvBD": {
                        "attributes": {
                          "name": "lab"
                        },
                        "children": [
                          {
                            "fvRsCtx": {
                              "attributes": {
                                "tnFvCtxName": "infra"
                              }
                            }
                          }
                        ]
                      }
                    }
                  ]
                }
              }
            ]
          }
        }"""
        )
        uni = self.tree.polUni()
        uni.json = tree
        uni.json.should_not.be.different_of(tree)

    def testXml(self):
        uni = self.tree.polUni()
        tenant = uni.fvTenant('mgmt')
        tenant.xml.should_not.be.different_of('<fvTenant name="mgmt"/>\n')

        uni.xml.should_not.be.different_of(
            textwrap.dedent(
                """\
        <polUni>
          <fvTenant name="mgmt"/>
        </polUni>
        """
            )
        )

    def testXmlSetter(self):
        tenant = self.tree.polUni().fvTenant('common')
        tenant.xml = '<fvTenant name="common" descr="Common tenant"/>'
        tenant.name.should.equal('common')
        tenant.descr.should.equal('Common tenant')

    def testXmlSetterTree(self):
        uni = self.tree.polUni()
        tree = textwrap.dedent(
            """\
        <polUni>
          <fvTenant name="test">
            <fvBD name="lab">
              <fvRsCtx tnFvCtxName="infra"/>
            </fvBD>
          </fvTenant>
        </polUni>
        """
        )
        uni.xml = tree
        uni.xml.should_not.be.different_of(tree)

    def testMoWithNoNamingProperties(self):
        uni = self.tree.polUni()
        uni.fvTenant('test').fvBD('lab').fvRsCtx().tnFvCtxName = 'infra'
        uni.xml.should_not.be.different_of(
            textwrap.dedent(
                """\
        <polUni>
          <fvTenant name="test">
            <fvBD name="lab">
              <fvRsCtx tnFvCtxName="infra"/>
            </fvBD>
          </fvTenant>
        </polUni>
        """
            )
        )

    def testPropertySetter(self):
        tenant = self.tree.polUni().fvTenant('mgmt')
        tenant.descr.should.be(None)
        tenant.descr = 'Sample description'
        tenant.descr.should.equal('Sample description')
        et = etree.XML(tenant.xml)
        et.tag.should.equal('fvTenant')
        et.attrib['name'].should.equal('mgmt')
        et.attrib['descr'].should.equal('Sample description')

    def test_mo_chaining(self):
        uni = self.tree.polUni()
        (
            uni.fvTenant('test')
            .fvCtx('infra')
            .up()
            .fvBD('lab')
            .fvRsCtx(tnFvCtxName='infra')
            .up(2)
            .fvBD('hr')
            .fvRsCtx(tnFvCtxName='infra')
        )
        uni.xml.should_not.be.different_of(
            textwrap.dedent(
                """\
        <polUni>
          <fvTenant name="test">
            <fvCtx name="infra"/>
            <fvBD name="lab">
              <fvRsCtx tnFvCtxName="infra"/>
            </fvBD>
            <fvBD name="hr">
              <fvRsCtx tnFvCtxName="infra"/>
            </fvBD>
          </fvTenant>
        </polUni>
        """
            )
        )

    def testNotEnoughNamingProperties(self):
        uni = self.tree.polUni()
        uni.fvBDDef.when.called_with('dontcare').should.throw(
            pyaci.errors.MoError,
            'Class `fvBDDef` requires 2 naming properties, ' 'but only 1 were provided',
        )

    def testNoNamingProperties(self):
        uni = self.tree.polUni()
        uni.fvBDDef.when.called_with().should.throw(
            pyaci.errors.MoError, 'Missing naming property `bdDn` for class `fvBDDef`'
        )

    def test_up_too_many(self):
        uni = self.tree.polUni()
        uni.up.when.called_with(2).should.throw(pyaci.errors.MoError, 'Reached top_root after 1 levels')

    def test_parse_xml_without_dn(self):
        xml = textwrap.dedent(
            """\
        <?xml version="1.0" encoding="UTF-8"?>
        <imdata totalCount="1">
            <fvTenant name="mgmt"/>
        </imdata>"""
        )
        (
            self.tree.parse_xml_response.when.called_with(xml).should.throw(
                pyaci.errors.MoError,
                'Property `dn` not found in element <fvTenant name="mgmt"/>',
            )
        )

    def test_parse_json_without_dn(self):
        text = textwrap.dedent(
            """\
        {
          "imdata":[
            {
              "fvTenant":{
                "attributes":{
                  "name":"mgmt"
                }
              }
            }
          ],
          "totalCount":"1"
        }
        """
        )
        (
            self.tree.parse_json_response.when.called_with(text).should.throw(
                pyaci.errors.MoError, 'Property `dn` not found in dict'
            )
        )

    def test_wrong_xml_element(self):
        et = etree.XML('<fvTenant name="test"/>')
        self.tree.polUni()._from_xml_element.when.called_with(et).should.throw(
            pyaci.errors.MoError,
            'Root element tag `fvTenant` does not match with class `polUni`',
        )


class LoginTests(unittest.TestCase):
    def setUp(self):
        self.login = pyaci.Node('http://localhost').methods.login('jsmith', 'secret')

    def testCreation(self):
        self.login._url().should.equal('http://localhost/api/aaaLogin.xml')
        et = etree.XML(self.login.xml)
        et.tag.should.equal('aaaUser')
        et.attrib['name'].should.equal('jsmith')
        et.attrib['pwd'].should.equal('secret')
        self.login.json.should.equal(
            textwrap.dedent(
                """\
        {
          "aaaUser": {
            "attributes": {
              "name": "jsmith",
              "pwd": "secret"
            }
          }
        }"""
            )
        )

    @httpretty.activate
    def testJsonPOST(self):
        httpretty.register_uri(httpretty.POST, 'http://localhost/api/aaaLogin.json')
        self.login.post(format='json')
        (httpretty.last_request().method).should.equal('POST')
        (httpretty.last_request().path).should.equal('/api/aaaLogin.json')
        (httpretty.last_request().body.decode('utf-8')).should.equal(self.login.json)

    @httpretty.activate
    def testXmlPOST(self):
        xml_body = """<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1">
<aaaLogin token="f00AAAAAAAAAAAAAAAAAAK4wjyQODSwoW3hizW066Ts6Gs2S4fkFZf6XhK32II8gZrRrgVGF2Y0pPs05FntrA6LCwXFWicPGpgsUp+SqTJdHZMeQrn45HBxJrmSJKtuYiqCX5Qc5P67Qq+c4w+VDcsHZxXe7KqeUs1TfKlXvvco8CwPOCRWJzMly0ArRsEL6c4t5zQTYpy9XsGwQEWJD/A==" siteFingerprint="UAViQctMne4xvtyZ" refreshTimeoutSeconds="600" maximumLifetimeSeconds="86400" guiIdleTimeoutSeconds="1200" restTimeoutSeconds="90" creationTime="1545696032" firstLoginTime="1545696032" userName="admin" remoteUser="false" unixUserId="15374" sessionId="LlQAR9nARFiVBAJWpwrTBQ==" lastName="" firstName="" changePassword="no" version="4.1(0.90b)" buildTime="Fri Oct 26 16:18:38 PDT 2018" node="topology/pod-1/node-1">
<aaaUserDomain name="all" rolesR="admin" rolesW="admin">
<aaaReadRoles/>
<aaaWriteRoles>
<role name="admin"/>
</aaaWriteRoles>
</aaaUserDomain>
<DnDomainMapEntry dn="uni/tn-mgmt" readPrivileges="admin" writePrivileges="admin"/>
<DnDomainMapEntry dn="uni/tn-infra" readPrivileges="admin" writePrivileges="admin"/>
<DnDomainMapEntry dn="uni/tn-common" readPrivileges="admin" writePrivileges="admin"/>
</aaaLogin></imdata>"""
        httpretty.register_uri(
            httpretty.POST,
            'http://localhost/api/aaaLogin.xml',
            body=xml_body,
            content_type='application/xml',
            status=200,
        )

        self.login.post(format='xml')
        (httpretty.last_request().method).should.equal('POST')
        (httpretty.last_request().path).should.equal('/api/aaaLogin.xml')
        (httpretty.last_request().body.decode('utf-8')).should.equal(self.login.xml)


class AppLoginTests(unittest.TestCase):
    def setUp(self):
        self.login = pyaci.Node('http://localhost').methods.app_login('acme')

    def testCreation(self):
        self.login._url().should.equal('http://localhost/api/requestAppToken.xml')
        et = etree.XML(self.login.xml)
        et.tag.should.equal('aaaAppToken')
        et.attrib['appName'].should.equal('acme')
        self.login.json.should.equal(
            textwrap.dedent(
                """\
        {
          "aaaAppToken": {
            "attributes": {
              "appName": "acme"
            }
          }
        }"""
            )
        )

    @httpretty.activate
    def testJsonPOST(self):
        httpretty.register_uri(httpretty.POST, 'http://localhost/api/requestAppToken.json')
        self.login.post(format='json')
        (httpretty.last_request().method).should.equal('POST')
        (httpretty.last_request().path).should.equal('/api/requestAppToken.json')
        (httpretty.last_request().body.decode('utf-8')).should.equal(self.login.json)

    @httpretty.activate
    def testXmlPOST(self):
        xml_body = """<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1">
<aaaLogin token="f00AAAAAAAAAAAAAAAAAAK4wjyQODSwoW3hizW066Ts6Gs2S4fkFZf6XhK32II8gZrRrgVGF2Y0pPs05FntrA6LCwXFWicPGpgsUp+SqTJdHZMeQrn45HBxJrmSJKtuYiqCX5Qc5P67Qq+c4w+VDcsHZxXe7KqeUs1TfKlXvvco8CwPOCRWJzMly0ArRsEL6c4t5zQTYpy9XsGwQEWJD/A==" siteFingerprint="UAViQctMne4xvtyZ" refreshTimeoutSeconds="600" maximumLifetimeSeconds="86400" guiIdleTimeoutSeconds="1200" restTimeoutSeconds="90" creationTime="1545696032" firstLoginTime="1545696032" userName="admin" remoteUser="false" unixUserId="15374" sessionId="LlQAR9nARFiVBAJWpwrTBQ==" lastName="" firstName="" changePassword="no" version="4.1(0.90b)" buildTime="Fri Oct 26 16:18:38 PDT 2018" node="topology/pod-1/node-1">
<aaaUserDomain name="all" rolesR="admin" rolesW="admin">
<aaaReadRoles/>
<aaaWriteRoles>
<role name="admin"/>
</aaaWriteRoles>
</aaaUserDomain>
<DnDomainMapEntry dn="uni/tn-mgmt" readPrivileges="admin" writePrivileges="admin"/>
<DnDomainMapEntry dn="uni/tn-infra" readPrivileges="admin" writePrivileges="admin"/>
<DnDomainMapEntry dn="uni/tn-common" readPrivileges="admin" writePrivileges="admin"/>
</aaaLogin></imdata>"""
        httpretty.register_uri(
            httpretty.POST,
            'http://localhost/api/requestAppToken.xml',
            body=xml_body,
            content_type='application/xml',
            status=200,
        )

        self.login.post(format='xml')
        (httpretty.last_request().method).should.equal('POST')
        (httpretty.last_request().path).should.equal('/api/requestAppToken.xml')
        (httpretty.last_request().body.decode('utf-8')).should.equal(self.login.xml)
        (
            self.login._root_api()
            .session.cookies.get('APIC-cookie')
            .should.equal(
                'f00AAAAAAAAAAAAAAAAAAK4wjyQODSwoW3hizW066Ts6Gs2S4fkFZf6XhK32II8gZrRrgVGF2Y0pPs05FntrA6LCwXFWicPGpgsUp+SqTJdHZMeQrn45HBxJrmSJKtuYiqCX5Qc5P67Qq+c4w+VDcsHZxXe7KqeUs1TfKlXvvco8CwPOCRWJzMly0ArRsEL6c4t5zQTYpy9XsGwQEWJD/A=='
            )
        )


class LogoutTests(unittest.TestCase):
    def setUp(self):
        self.node = pyaci.Node('http://localhost')
        self.login = self.node.methods.login('jsmith', 'secret')
        self.logout = self.node.methods.logout('jsmith')

    def testCreation(self):
        self.logout._url().should.equal('http://localhost/api/aaaLogout.xml')
        et = etree.XML(self.logout.xml)
        et.tag.should.equal('aaaUser')
        et.attrib['name'].should.equal('jsmith')
        self.logout.json.should.equal(
            textwrap.dedent(
                """\
        {
          "aaaUser": {
            "attributes": {
              "name": "jsmith"
            }
          }
        }"""
            )
        )

    @httpretty.activate
    def testJsonPOST(self):
        httpretty.register_uri(httpretty.POST, 'http://localhost/api/aaaLogout.json')
        self.logout.post(format='json')
        (httpretty.last_request().method).should.equal('POST')
        (httpretty.last_request().path).should.equal('/api/aaaLogout.json')
        (httpretty.last_request().body.decode('utf-8')).should.equal(self.logout.json)

    @httpretty.activate
    def testXmlPOST(self):
        httpretty.register_uri(httpretty.POST, 'http://localhost/api/aaaLogout.xml')

        self.logout.post(format='xml')
        (httpretty.last_request().method).should.equal('POST')
        (httpretty.last_request().path).should.equal('/api/aaaLogout.xml')
        (httpretty.last_request().body.decode('utf-8')).should.equal(self.logout.xml)


class LoginRefreshTests(unittest.TestCase):
    def setUp(self):
        self.login = pyaci.Node('http://localhost').methods.login_refresh()

    def testCreation(self):
        self.login._url().should.equal('http://localhost/api/aaaRefresh.xml')

    @httpretty.activate
    def testAaaUserJsonGET(self):
        httpretty.register_uri(httpretty.GET, 'http://localhost/api/aaaRefresh.json')
        self.login.get(format='json')
        (httpretty.last_request().method).should.equal('GET')
        (httpretty.last_request().path).should.equal('/api/aaaRefresh.json')


class AutoRefreshTests(unittest.TestCase):
    def setUp(self):
        self.node = pyaci.Node('http://localhost')
        self.login = self.node.methods.login('admin', 'password', auto_refresh=True)

    @httpretty.activate
    def test_refresh_once(self):
        login_xml_body = """<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1">
<aaaLogin token="f00AAAAAAAAAAAAAAAAAAK4wjyQODSwoW3hizW066Ts6Gs2S4fkFZf6XhK32II8gZrRrgVGF2Y0pPs05FntrA6LCwXFWicPGpgsUp+SqTJdHZMeQrn45HBxJrmSJKtuYiqCX5Qc5P67Qq+c4w+VDcsHZxXe7KqeUs1TfKlXvvco8CwPOCRWJzMly0ArRsEL6c4t5zQTYpy9XsGwQEWJD/A==" siteFingerprint="UAViQctMne4xvtyZ" refreshTimeoutSeconds="600" maximumLifetimeSeconds="86400" guiIdleTimeoutSeconds="1200" restTimeoutSeconds="90" creationTime="1545696032" firstLoginTime="1545696032" userName="admin" remoteUser="false" unixUserId="15374" sessionId="LlQAR9nARFiVBAJWpwrTBQ==" lastName="" firstName="" changePassword="no" version="4.1(0.90b)" buildTime="Fri Oct 26 16:18:38 PDT 2018" node="topology/pod-1/node-1">
<aaaUserDomain name="all" rolesR="admin" rolesW="admin">
<aaaReadRoles/>
<aaaWriteRoles>
<role name="admin"/>
</aaaWriteRoles>
</aaaUserDomain>
<DnDomainMapEntry dn="uni/tn-mgmt" readPrivileges="admin" writePrivileges="admin"/>
<DnDomainMapEntry dn="uni/tn-infra" readPrivileges="admin" writePrivileges="admin"/>
<DnDomainMapEntry dn="uni/tn-common" readPrivileges="admin" writePrivileges="admin"/>
</aaaLogin></imdata>"""
        httpretty.register_uri(
            httpretty.POST,
            'http://localhost/api/aaaLogin.xml',
            body=login_xml_body,
            content_type='application/xml',
            status=200,
        )

        self.login.post(format='xml')
        refresh_xml_body = """<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1">
<aaaLogin token="700AAAAAAAAAAAAAAAAAAEdiM3Vap8h/9pkqbxgvrOKvPvYW8nkyXIAILMWqdcXSADxXZPE06nsifq+kslkI2UECxR+977d9+yaLtBhK0sz9ugT+id+GFVjh6irHCfIcQDAFeOEYo7u8hxqD84f6iIvGnDzQdZpD4256UkJAZHActeNQzVeDiVS5ldaSEqzAh1Df5IITKKASySUCHi71wg==" siteFingerprint="UAViQctMne4xvtyZ" refreshTimeoutSeconds="600" maximumLifetimeSeconds="86400" guiIdleTimeoutSeconds="1200" restTimeoutSeconds="90" creationTime="1545699898" firstLoginTime="1545699898" userName="admin" remoteUser="false" unixUserId="15374" sessionId="joR4ziDdTeedI1lybx1bjQ==" lastName="" firstName="" changePassword="no" version="4.1(0.90b)" buildTime="Fri Oct 26 16:18:38 PDT 2018" node="topology/pod-1/node-1">
<aaaUserDomain name="all" readRoleBitmask="0" writeRoleBitmask="1"/>
</aaaLogin></imdata>"""
        httpretty.register_uri(
            httpretty.GET,
            'http://localhost/api/aaaRefresh.xml',
            body=refresh_xml_body,
            content_type='application/xml',
            status=200,
        )
        self.node._login['next_refresh_before'] = int(time.time()) - 120
        self.node._auto_refresh_thread._refresh_login_if_needed()
        (httpretty.last_request().method).should.equal('GET')
        (httpretty.last_request().path).should.equal('/api/aaaRefresh.xml')

        httpretty.register_uri(
            httpretty.GET,
            'http://localhost/api/subscriptionRefresh.xml?id=123456789',
            body='',
            status=200,
        )
        self.node._ws_events = {}
        self.node._ws_events['123456789'] = []
        self.node._ws_last_refresh = int(time.time()) - 60
        self.node._auto_refresh_thread._refresh_subscriptions_if_needed()
        (httpretty.last_request().method).should.equal('GET')
        (httpretty.last_request().path).should.equal('/api/subscriptionRefresh.xml?id=123456789')


class RefreshSubscriptionTests(unittest.TestCase):
    def setUp(self):
        self.node = pyaci.Node('http://localhost')
        self.rfs = self.node.methods.refresh_subscriptions('100001')

    def test_creation(self):
        self.rfs._url().should.equal('http://localhost/api/subscriptionRefresh.xml')

    @httpretty.activate
    def test_json_get(self):
        httpretty.register_uri(httpretty.GET, 'http://localhost/api/subscriptionRefresh.json?id=100001')
        self.rfs.get(format='json')
        (httpretty.last_request().method).should.equal('GET')
        (httpretty.last_request().path).should.equal('/api/subscriptionRefresh.json?id=100001')

    @httpretty.activate
    def test_xml_get(self):
        httpretty.register_uri(httpretty.GET, 'http://localhost/api/subscriptionRefresh.xml?id=100001')

        self.rfs.get(format='xml')
        (httpretty.last_request().method).should.equal('GET')
        (httpretty.last_request().path).should.equal('/api/subscriptionRefresh.xml?id=100001')


class ResolveClassTests(unittest.TestCase):
    def setUp(self):
        self.resolve = pyaci.Node('http://localhost').methods.resolve_class('fvTenant')

    def testCreation(self):
        self.resolve._url().should.equal('http://localhost/api/class/fvTenant.xml')

    @httpretty.activate
    def testJsonGET(self):
        httpretty.register_uri(
            httpretty.GET,
            'http://localhost/api/class/fvTenant.json',
            body=textwrap.dedent(
                """\
        {
          "imdata":[
            {
              "fvTenant":{
                "attributes":{
                  "childAction":"",
                  "descr":"Test",
                  "dn":"uni/tn-mgmt",
                  "lcOwn":"local",
                  "modTs":"2014-10-14T04:15:15.589+00:00",
                  "monPolDn":"uni/tn-common/monepg-default",
                  "name":"mgmt",
                  "ownerKey":"",
                  "ownerTag":"",
                  "status":"",
                  "uid":"0"
                }
              }
            }
          ],
          "totalCount":"1"
        }
                               """
            ),
        )
        result = self.resolve.get(format='json')
        (httpretty.last_request().method).should.equal('GET')
        (httpretty.last_request().path).should.equal('/api/class/fvTenant.json')
        result.shouldnt.be.empty
        tenant = result[0]
        tenant.name.should.equal('mgmt')


class MethodsTests(unittest.TestCase):
    def setUp(self):
        self.url = 'http://localhost'
        self.tree = pyaci.Node(self.url).mit

    @httpretty.activate
    def test_json_mo_get(self):
        httpretty.register_uri(
            httpretty.GET,
            'http://localhost/api/mo/uni/tn-mgmt.json',
            body=textwrap.dedent(
                """\
        {
          "imdata":[
            {
              "fvTenant":{
                "attributes":{
                  "childAction":"",
                  "descr":"Test",
                  "dn":"uni/tn-mgmt",
                  "lcOwn":"local",
                  "modTs":"2014-10-14T04:15:15.589+00:00",
                  "monPolDn":"uni/tn-common/monepg-default",
                  "name":"mgmt",
                  "ownerKey":"",
                  "ownerTag":"",
                  "status":"",
                  "uid":"0"
                }
              }
            }
          ],
          "totalCount":"1"
        }
                               """
            ),
        )
        result = self.tree.polUni().fvTenant('mgmt').get(format='json')
        (httpretty.last_request().method).should.equal('GET')
        (httpretty.last_request().path).should.equal('/api/mo/uni/tn-mgmt.json')

        result = result[0]
        result.should.be.a(pyaci.core.Mo)
        result.class_name.should.equal('fvTenant')
        result.descr.should.equal('Test')

    @httpretty.activate
    def test_mo_xml_get(self):
        httpretty.register_uri(
            httpretty.GET,
            'http://localhost/api/mo/uni/tn-mgmt.xml',
            body=textwrap.dedent(
                """\
        <?xml version="1.0" encoding="UTF-8"?>
        <imdata totalCount="1">
            <fvTenant childAction="" descr="Test" dn="uni/tn-mgmt"
                      lcOwn="local" modTs="2014-10-14T04:15:15.589+00:00"
                      monPolDn="uni/tn-common/monepg-default" name="mgmt"
                      ownerKey="" ownerTag="" status="" uid="0"/>
        </imdata>
                               """
            ),
        )
        result = self.tree.polUni().fvTenant('mgmt').get(format='xml')
        (httpretty.last_request().method).should.equal('GET')
        (httpretty.last_request().path).should.equal('/api/mo/uni/tn-mgmt.xml')

        result = result[0]
        result.should.be.a(pyaci.core.Mo)
        result.class_name.should.equal('fvTenant')
        result.descr.should.equal('Test')

    @httpretty.activate
    def test_mo_xml_get_with_options(self):
        httpretty.register_uri(
            httpretty.GET,
            'http://localhost/api/mo/uni/tn-mgmt.xml?rsp-subtree=full',
            body=textwrap.dedent(
                """\
        <?xml version="1.0" encoding="UTF-8"?>
        <imdata totalCount="1">
            <fvTenant childAction="" descr="Test" dn="uni/tn-mgmt"
                      lcOwn="local" modTs="2014-10-14T04:15:15.589+00:00"
                      monPolDn="uni/tn-common/monepg-default" name="mgmt"
                      ownerKey="" ownerTag="" status="" uid="0"/>
        </imdata>
                               """
            ),
        )
        options = {'rsp-subtree': 'full'}
        result = self.tree.polUni().fvTenant('mgmt').get(format='xml', **options)
        (httpretty.last_request().method).should.equal('GET')
        (httpretty.last_request().path).should_not.be.different_of('/api/mo/uni/tn-mgmt.xml?rsp-subtree=full')

        result = result[0]
        result.should.be.a(pyaci.core.Mo)
        result.class_name.should.equal('fvTenant')
        result.descr.should.equal('Test')

    @httpretty.activate
    def test_mo_json_delete(self):
        httpretty.register_uri(httpretty.DELETE, 'http://localhost/api/mo/uni/tn-test.json')
        self.tree.polUni().fvTenant('test').delete(format='json')
        (httpretty.last_request().method).should.equal('DELETE')
        (httpretty.last_request().path).should.equal('/api/mo/uni/tn-test.json')

    @httpretty.activate
    def test_mo_xml_delete(self):
        httpretty.register_uri(httpretty.DELETE, 'http://localhost/api/mo/uni/tn-test.xml')
        self.tree.polUni().fvTenant('test').delete(format='xml')
        (httpretty.last_request().method).should.equal('DELETE')
        (httpretty.last_request().path).should.equal('/api/mo/uni/tn-test.xml')

    @httpretty.activate
    def test_mo_json_post(self):
        httpretty.register_uri(httpretty.POST, 'http://localhost/api/mo/uni/tn-test.json')
        tenant = self.tree.polUni().fvTenant('test')
        tenant.post(format='json')
        (httpretty.last_request().method).should.equal('POST')
        (httpretty.last_request().path).should.equal('/api/mo/uni/tn-test.json')
        (httpretty.last_request().body.decode('utf-8')).should.equal(tenant.json)

    @httpretty.activate
    def test_mo_xml_post(self):
        httpretty.register_uri(httpretty.POST, 'http://localhost/api/mo/uni/tn-test.xml')
        tenant = self.tree.polUni().fvTenant('test')
        tenant.post(format='xml')
        (httpretty.last_request().method).should.equal('POST')
        (httpretty.last_request().path).should.equal('/api/mo/uni/tn-test.xml')
        (httpretty.last_request().body.decode('utf8')).should.equal(tenant.xml)
