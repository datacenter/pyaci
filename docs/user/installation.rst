Installation
============

Package Installation
--------------------

You can install from a local or remote archive using ``pip``::

  pip install https://github.com/datacenter/pyaci/archive/master.zip

You can also install from a local directory using ``pip``::

  pip install -e .


Meta Generation
---------------

PyACI requires metadata about ACI model. PyACI looks in the home
directory under ``.aci-meta`` directory for the meta files. By
default, PyACI requires the meta file (or symbolic link to the meta
file) at ``~/.aci-meta/aci-meta.json``.

A utility named ``rmetagen.py`` is provided to generate the required
meta file by connecting to an APIC. This utility requires login
credetials to APIC.

Here is a sample usage::

   rmetagen.py -u admin apic1.example.org
   Enter admin password for apic1.example.org
   APIC is running version 1.2(0.104a)
   Copying metagen.py to APIC
   Invoking metagen.py on APIC
   Copying generated meta from APIC to /Users/praveen/.aci-meta/aci-meta.1.2(0.104a).json
   No default meta exist. Setting the current meta as the default.
