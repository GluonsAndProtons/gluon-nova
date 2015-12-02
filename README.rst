===============================
gluon-nova
===============================

OpenStack Gluon acts as a port arbiter between Nova and port-provider
such as Neutron.  This is the plugin for Nova to drive Gluon.

Note that at the moment Nova doesn't use stevedore for this, so to configure the
port provider, you must use the whole path of the Gluon plugin class thus:

    [DEFAULT]
    network_api_class=gluon_nova.api.API

* Free software: Apache license
* Documentation: http://docs.openstack.org/developer/gluon
* Source: http://github.com/iawells/gluon-nova
* Bugs: http://github.com/iawells/gluon-nova/issues

Features
--------

* Provides ports.
* Provides addresses, MACs.

Anti-features
-------------

Does not provide networks, subnets, routers or many of the other things that
Nova would like to be able to offer as API features.  As yet the appropriate
Nova config (and possibly code changes) have not been determined, so many of
these commands will return a 500 rather than a 404 when used.

Does not provide the ability to create ports.  For that, you should go to the
port provider.  Nova's API currently provides the ability to auto-create ports
from a network (--nic net-id=... on the CLI, e.g.) but this cannot be
duplicated without a network.  We're working on an alternative to this, but
in the meantime you should:

    neutron port-create ... # or other service
    nova boot --nic port-id ...

(Note for any developer interested in this: the problem lies in Nova-the-server
not Nova-the-CLI-command calling Neutron to make the port create happen.  If
the server calls, it must now call Gluon and pass some distinguishing mark
indicating what it's actually looking to do, e.g. provider=neutron +
network = net-id (which it can't validate any more) + binding-type=direct.
Given that Neutron is not the only port provider that may be in use (it may not
even be in use itself) then Nova cannot possibly know how to create ports
in all circumstances, which precludes it from validating any of the --nic
options as it does now.  There's a knotty problem to solve here.)

Does not currently respect mah authoritaye.  Needs work so that it understands
the distinctions between:

* I may create a port with these parameters (per previous point, may not
  be relevant anyway since port creates don't currently go via Gluon)

* I may bind a VM to this port (as in, I am a compute service and it is
  my prerogative to bind VMs or other compute services to ports)

* The caller of the compute service is permitted to use this port for binding
  (as in, a VM has been created in Nova and the user requesting it has asked for
  a bind to a specific port; is it permitted?)

Also, perhaps:

* I, an end user, would like to bind a port to something that's not a compute
  VM but that I may have access to (do I call Gluon directly for this, do I call
  another service that has rights to Gluon, do I call the backend network service
  directly?)

