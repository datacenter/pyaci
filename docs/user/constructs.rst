Constructs
==========

PyACI tries to provide a minimal set of constructs, that should be
enough to achieve most of the tasks that would otherwise be achieved
using the REST API.

Node
----

A Node represents the ACI fabric node that one would be communicating
with. This could be a controller, leaf or spine. A Node object can be
instantiated by specifying the REST URL for communicating with the
underlying node.

    >>> from pyaci import Node
    >>> apic = Node('https://192.168.10.1')

For more information, refer to Node documentation.

API Objects
-----------

Once a Node has been instantiated, a variety of API objects can be
spawned from that. There are two classes of these objects:

- Methods
- Managed objects

All these objects support one, or many REST operations. The objects
don't interact with the underlying physical node by themeselves. In
order to interact, one of the supporte REST construct has to be
invoked on them. There are utmost three REST constructs supported on
these objects:

- GET
- POST
- DELETE

Methods
-------

Any REST request that does not operate on managed objects is modeled
as a method. The following are some of the methods that are currently
supported:

Login
~~~~~

This method supports a simple password based login.

    >>> apic.methods.Login('admin', 'password').POST()

LoginRefresh
~~~~~~~~~~~~

This method refreshes an existing session.

    >>> apic.methods.LoginRefresh().GET()

ChangeCert
~~~~~~~~~~

This method is used to add or change X509 certificate that is used for
authenticating a user.

    >>> apic.methods.ChangeCert('admin', 'it', '/path/to/certificate').POST()

UploadPackage
~~~~~~~~~~~~~

This method is used to upload an Layer 4 - Layer 7 services package.

    >>> apic.methods.UploadPackage('/path/to/package/file')

Managed Objects
---------------

ACI managed objects can be instantiated fromt the Node object using a
local Managed Information Tree (MIT). Each invocation of `mit`
property on the Node object will result in a different local MIT which
can be used as a local cache. For instance, a local polUni object can
be instantiated as follows:

    >>> mit = apic.mit
    >>> mit.polUni()

Please note that at this point this object is only locally
instantiated. No communication with the underlying node is involved
yet.

At this point, you would have noticed that . notation is used to chain
object containment hierarchy. The same . notation is also used for
accessing properties of an object.

    >>> ctx = apic.mit.polUni().fvTenant('test').fvCtx('lab')
    >>> ctx.descr = 'Lab network'
    >>> print ctx.descr
    Lab network
    >>> print ctx.Xml
    <fvCtx name="lab" descr="Lab network"/>

When using . notation for a child object, one should specify the class
name, followed by a paranthesis that takes naming properties as either
arguments, or keyword arguments. One can also specify non naming
properties as keyword arguments.

    >>> uni = apic.mit.polUni()
    >>> tenant = uni.fvTenant('demo')
    >>> print tenant.Xml
    <fvTenant name="demo"/>
    
    >>> tenant = uni.fvTenant(name='demo')
    >>> print tenant.Xml
    <fvTenant name="demo"/>
    
    >>> tenant = uni.fvTenant('demo', descr='Demo tenant')
    >>> print tenant.Xml
    <fvTenant name="demo" descr="Demo tenant"/>


POST
~~~~

Local managed objects are posted to underlying node using POST()
method on the object. The following example shows posting of a new
tenant to APIC.

    >>> apic.mit.polUni().fvTenant('test').POST()

This method posts the object, and the entire subtree under that
object. For instance, a tenant, private network, bridge domain, and an
end-point group can all be created in a single shot and the subtree
can be posted as follows.

    >>> uni = apic.mit.polUni()
    >>> (uni.fvTenant('demo').fvCtx('test').Up().
    ...  fvBD('lab').fvRsCtx(tnFvCtxName='test').Up(2).
    ...  fvAp('hadoop').fvAEPg('hbase').fvRsBd(tnFvBDName='lab'))
    >>> print uni.Xml
    <polUni>
      <fvTenant name="demo">
        <fvCtx name="test"/>
        <fvAp name="hadoop">
          <fvAEPg name="hbase">
            <fvRsBd tnFvBDName="lab"/>
          </fvAEPg>
        </fvAp>
        <fvBD name="lab">
          <fvRsCtx tnFvCtxName="test"/>
        </fvBD>
      </fvTenant>
    </polUni>
    >>> uni.POST()

DELETE
~~~~~~

Local managed objects can be deleted from the underlying node using
DELETE() method on that object. A fvCtx object can be deleted as shown
below:

    >>> apic.mit.polUni().fvTenant('demo').fvCtx('test').DELETE()

Please note that the local cached managed objects still remain even
though it is deleted from APIC.

GET
~~~

Local managed objects can be fetch from the underlying node using
GET() method on that object. GET() takes other option to affect the
scope of the query. We'll look at them later. To begin with, a fvBD
can be fetched as follows:

    >>> bd = apic.mit.polUni().fvTenant('common').fvBD('default')
    >>> result = bd.GET()
    >>> type(result)
    <type 'list'>
    >>> print len(result)
    1
    >>> print result[0].Dn
    uni/tn-common/BD-default

Please note that the GET() method returs a list. The monadic nature of
list is taken advantage to represent the result of a query that can
fetch 0, 1 or more objects. It should also be noted that the local
managed object is automatically updated with the fetched values.

    >>> print bd.Xml
    <fvBD dn="uni/tn-common/BD-default" uid="0" arpFlood="no" seg="16678778" unicastRoute="yes" unkMcastAct="flood" descr="" llAddr="::" monPolDn="uni/tn-common/monepg-default" modTs="2015-05-27T22:51:09.820+00:00" scope="2195456" status="" bcastP="225.0.248.224" mac="00:22:BD:F8:19:FF" epMoveDetectMode="" ownerTag="" childAction="" lcOwn="local" ownerKey="" name="default" unkMacUcastAct="proxy" multiDstPktAct="bd-flood" limitIpLearnToSubnets="no" mtu="inherit" pcTag="16386"/>

GET() method can be combined with various options to result in more
powerful queries like fetching objects of a certain class, or subtree,
etc. For instance, all tenants can be queries as follows:

    >>> from pyaci import options
    >>> result = apic.mit.GET(**options.subtreeClass('fvTenant'))
    >>> for tenant in result:
    ...     print tenant.Dn
    ...
    uni/tn-common
    uni/tn-infra
    uni/tn-cokecorp
    uni/tn-mgmt

The entire subtree of management tenant can be queried as follows:

    >>> result = apic.mit.polUni().fvTenant('mgmt').GET(**options.subtree)
    >>> for tenant in result:
    ...     print tenant.Dn
    ...
    uni/tn-mgmt/domain-mgmt
    uni/tn-mgmt/BD-inb/rsBDToNdP
    uni/tn-mgmt/BD-inb/rsbdToEpRet
    uni/tn-mgmt/BD-inb/rsctx
    uni/tn-mgmt/BD-inb/rsigmpsn
    uni/tn-mgmt/BD-inb
    uni/tn-mgmt/ctx-oob/rsbgpCtxPol
    uni/tn-mgmt/ctx-oob/rsctxToEpRet
    uni/tn-mgmt/ctx-oob/rsctxToExtRouteTagPol
    uni/tn-mgmt/ctx-oob/rsospfCtxPol
    uni/tn-mgmt/ctx-oob/rtmgmtOoBCtx-[uni/tn-mgmt/mgmtp-default/oob-default]
    uni/tn-mgmt/ctx-oob/any
    uni/tn-mgmt/ctx-oob
    uni/tn-mgmt/ctx-inb/rsbgpCtxPol
    uni/tn-mgmt/ctx-inb/rsctxToEpRet
    uni/tn-mgmt/ctx-inb/rsctxToExtRouteTagPol
    uni/tn-mgmt/ctx-inb/rsospfCtxPol
    uni/tn-mgmt/ctx-inb/rtctx-[uni/tn-mgmt/BD-inb]
    uni/tn-mgmt/ctx-inb/any
    uni/tn-mgmt/ctx-inb
    uni/tn-mgmt/rsTenantMonPol
    uni/tn-mgmt/extmgmt-default
    uni/tn-mgmt/mgmtp-default/oob-default/rsooBCtx
    uni/tn-mgmt/mgmtp-default/oob-default
    uni/tn-mgmt/mgmtp-default
    uni/tn-mgmt

Audit logs for an object can be fetch as follows:

    >>> tenant = apic.mit.polUni().fvTenant('demo')
    >>> tenant.descr = 'Test 1'
    >>> tenant.POST()
    >>> tenant.descr = 'Test 2'
    >>> tenant.POST()
    >>> result = tenant.GET(**options.auditLogs)
    >>> for change in result:
    ...     print change.created, change.descr, change.changeSet
    ...
    2015-05-28T01:08:26.627+00:00 Tenant demo created descr:Test 1, name:demo
    2015-05-28T01:08:37.627+00:00 Tenant demo modified descr (Old: Test 1, New: Test 2)

Multiple options can be combined with & operator, and filters can be used as follows:

    >>> for node in apic.mit.GET(
    ...     **options.subtreeClass('fabricNode') &
    ...     options.filter(filters.Eq('fabricNode.role', 'leaf') |
    ...                    filters.Eq('fabricNode.role', 'spine'))):
    ...     print node.name, node.role
    ...
    leaf1 leaf
    spine2 spine
    spine1 spine
    leaf2 leaf

Managed Object Iterators
------------------------

Local MIT provides a constructe of object iterators. On a given
object, . notation can be used with (immediate) child class name
without a following paranthesis to access all children of that
class. For instance:

    >>> mit = apic.mit
    >>> mit.polUni().fvTenant('test')
    >>> mit.polUni().fvTenant('demo')
    >>> mit.polUni().fvTenant('finance')
    >>> for tenant in mit.polUni().fvTenant:
    ...     print tenant.Dn
    ...
    uni/tn-demo
    uni/tn-test
    uni/tn-finance

The use of iterators becomes more obvious when one is walking through
a subtree that is fetched from a node.

    >>> pod = apic.mit.fabricTopology().fabricPod('1')
    >>> pod.GET(**options.subtree)
    >>> for node in pod.fabricNode:
    ...     print node.name, node.role, node.fabricSt
    ...
    leaf2 leaf active
    spine1 spine active
    leaf1 leaf active
    apic1 controller unknown
    spine2 spine active

There is also a way to access all the children of a given object using
Children property.

    >>> pod = apic.mit.fabricTopology().fabricPod('1')
    >>> pod.GET(**options.subtree)
    >>> for child in pod.Children:
    ...     print child.Dn
    ...
    topology/pod-1/lnkcnt-102
    topology/pod-1/node-102
    topology/pod-1/paths-102
    topology/pod-1/paths-101
    topology/pod-1/node-101
    topology/pod-1/node-104
    topology/pod-1/paths-104
    topology/pod-1/lnkcnt-1
    topology/pod-1/lnkcnt-103
    topology/pod-1/path-101-102
    topology/pod-1/lnkcnt-101
    topology/pod-1/node-1
    topology/pod-1/lnkcnt-104
    topology/pod-1/node-103
    topology/pod-1/health
    topology/pod-1/paths-103
