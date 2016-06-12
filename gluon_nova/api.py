# Copyright 2012 OpenStack Foundation
# All Rights Reserved
# Copyright (c) 2012 NEC Corporation
# Copyright (c) 2015 Cisco Systems, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# The gluon_nova version of this file is a trimmed down and edited version of
# OpenStack's nova/network/neutronv2/api.py.

import time
import uuid

from keystoneclient import auth
from keystoneclient.auth.identity import v2 as v2_auth
from keystoneclient.auth import token_endpoint
from keystoneclient import session
from neutronclient.common import exceptions as gluon_client_exc
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils
import six

from nova.compute import utils as compute_utils
from nova import exception
from nova.i18n import _, _LE, _LI, _LW
from nova.network import base_api
from nova.network import model as network_model
from gluon_nova import constants
from nova import objects
from nova.pci import manager as pci_manager
from nova.pci import request as pci_request
from nova.pci import whitelist as pci_whitelist

from gluonclient import api as gluonclient

opts = [
    cfg.StrOpt('url',
               default='http://127.0.0.1:2704',
               help='URL for connecting to gluon'),
    cfg.StrOpt('region_name',
               help='Region name for connecting to gluon in admin context'),
]

OPT_GROUP = 'gluon'

CONF = cfg.CONF
CONF.register_opts(opts, OPT_GROUP)

deprecations = {}

session.Session.register_conf_options(CONF, OPT_GROUP,
                                      deprecated_opts=deprecations)
auth.register_conf_options(CONF, OPT_GROUP)


LOG = logging.getLogger(__name__)

# NOTE: these classes are practically speaking unneeded, but I've put them here for two reasons:
# 1. as a list of ABCs that this interface probably ought to support so that we can do better in
# Nova when the feature is not supported by the network plugin
# 2. as a documented list of functions I've actively not implemented (so that you know I've made
# a choice rather than forgotten them)
# We should, in theory, have implemented every function of the base API model.  It could, therefore,
# be converted to an ABC that expects complete implementation.

class NoNetworkSupportMixin(object):
    def _err(self):
        raise NotImplementedError("No L2 network support when using Gluon - use the backend")

    def get_all(self, context): self._err()
    def get(self, context, network_uuid): self._err()
    def create(self, context, **kwargs): self._err()
    def delete(self, context, network_uuid): self._err()
    def disassociate(self, context, network_uuid): self._err()
    def add_network_to_project(self, context, project_id, network_uuid=None): self._err()

class NoFixedIPSupportMixin(object):
    def _err(self):
        raise NotImplementedError("No fixed IP changing support when using Gluon - use the backend")

    def add_fixed_ip_to_instance(self, context, instance, network_id): self._err()
    def remove_fixed_ip_from_instance(self, context, instance, address): self._err()

class NoFloatingIPSupportMixin(object):
    def _err(self):
        raise NotImplementedError("No floating IP support when using Gluon - use the backend")

    def get_floating_ip(self, context, id): self._err()
    def get_floating_ip_pools(self, context): self._err()
    def get_floating_ip_by_address(self, context, address): self._err()
    def get_floating_ips_by_project(self, context): self._err()
    def get_instance_id_by_floating_address(self, context, address): self._err()
    def allocate_floating_ip(self, context, pool=None): self._err()
    def release_floating_ip(self, context, address,
                            affect_auto_assigned=False): self._err()
    def disassociate_and_release_floating_ip(self, context, instance,
                                             floating_ip): self._err()
    def associate_floating_ip(self, context, instance,
                              floating_address, fixed_address,
                              affect_auto_assigned=False): self._err()
    def disassociate_floating_ip(self, context, instance, address,
                                 affect_auto_assigned=False): self._err()


class NoDNSSupportMixin(object):
    def _err(self):
        raise NotImplementedError("No DNS support when using Gluon")

    def get_dns_domains(self, context): self._err()
    def add_dns_entry(self, context, address, name, dns_type, domain): self._err()
    def modify_dns_entry(self, context, name, address, domain): self._err()
    def delete_dns_entry(self, context, name, domain): self._err()
    def delete_dns_domain(self, context, domain): self._err()
    def get_dns_entries_by_address(self, context, address, domain): self._err()
    def get_dns_entries_by_name(self, context, name, domain): self._err()
    def create_private_dns_domain(self, context, domain, availability_zone): self._err()
    def create_public_dns_domain(self, context, domain, project=None): self._err()

class NoHostSetupRequiredMixin(object):
    def setup_networks_on_host(self, context, instance, host=None,
                               teardown=False):
        pass


SERVICE_NAME='nova'

# TODO - support:
# get_fixed_ip (by id)
# get_fixed_ip_address
# get_vifs_by_instance (?)
# get_vifs_by_mac_address
class API(base_api.NetworkAPI,
          NoNetworkSupportMixin, NoFixedIPSupportMixin, NoFloatingIPSupportMixin,
          NoDNSSupportMixin, NoHostSetupRequiredMixin):
    """API for interacting with the gluon 2.x API."""

    def __init__(self, skip_policy_check=False):
        super(API, self).__init__(skip_policy_check=skip_policy_check)
        self.client = gluonclient.ComputeServiceAPI(CONF.gluon.url,
                                                    SERVICE_NAME) # This last is our ownership name
    # .. and it being 'nova' means we can have one nova per gluon

    def _unbind_ports(self, context, ports):
        """Unbind the given ports.

        :param context: The request context.
        :param ports: list of port IDs.
        """

        for port_id in ports:
            try:
                self.client.unbind(port_id)
            except Exception:
                LOG.exception(_LE("Unable to clear device ID "
                                  "for port '%s'"), port_id)

    def allocate_for_instance(self, context, instance, **kwargs):
        """Allocate network resources for the instance.

        :param context: The request context.
        :param instance: nova.objects.instance.Instance object.
        :param requested_networks: optional value containing
            network_id, fixed_ip, and port_id
        :param security_groups: security groups to allocate for instance
        :param macs: None or a set of MAC addresses that the instance
            should use. macs is supplied by the hypervisor driver (contrast
            with requested_networks which is user supplied).
            NB: GluonV2 currently assigns hypervisor supplied MAC addresses
            to arbitrary networks, which requires openflow switches to
            function correctly if more than one network is being used with
            the bare metal hypervisor (which is the only one known to limit
            MAC addresses).
        :param dhcp_options: None or a set of key/value pairs that should
            determine the DHCP BOOTP response, eg. for PXE booting an instance
            configured with the baremetal hypervisor. It is expected that these
            are already formatted for the gluon v2 api. TODO and likely this is
	    not true...
            See nova/virt/driver.py:dhcp_options_for_instance for an example.
        """
        hypervisor_macs = kwargs.get('macs', None)

        # The gluon client and port_client (either the admin context or
        # tenant context) are read here. The reason for this is that there are
        # a number of different calls for the instance allocation.
        # We do not want to create a new gluon session for each of these
        # calls.
        client = self.client

        LOG.debug('allocate_for_instance()', instance=instance)

        # Not that this should ever happen, but we can't check permissions if
        # there is no owning project id on the instance.
        if not instance.project_id:
            msg = _('empty project id for instance %s')
            raise exception.InvalidInput(
                reason=msg % instance.uuid)

        # requested NICs, actually (networks for historical reasons)
        requested_networks = kwargs.get('requested_networks')

        # We are passed DHCP options, but we don't use them because our ports exist
        # already.  This is only for fresh ports.
        # dhcp_opts = kwargs.get('dhcp_options', None)

        # if this function is directly called without a requested_network param
        # or if it is indirectly called through allocate_port_for_instance()
        # with None params=(network_id=None, requested_ip=None, port_id=None,
        # pci_request_id=None):

        if (not requested_networks or len(requested_networks) == 0):
            # This used to mean 'attach to all networks', but Gluon
            # knows not of networks
            raise NotImplementedError("NICs must be explicitly bound to ports: %s" % requested_networks)

        for request in requested_networks:
            if request.port_id:

                # Check gluon has heard of this, and something else (another VM under Nova, or another
                # service than Nova) has not already started using it
                try:
                    unbound = client.is_unbound(request.port_id)
                    LOG.debug('This port %s is bound? %s' % (request.port_id, 'no' if unbound else 'yes'))
                    if not unbound:
                        raise exception.PortInUse(port_id=request.port_id)

                except gluon_client_exc.PortNotFoundClient:
                    raise exception.PortNotFound(port_id=request.port_id)
                # TODO ownership / rights check
                #if port['tenant_id'] != instance.project_id:
                #    raise exception.PortNotUsable(port_id=request.port_id,
                #                                  instance=instance.uuid)

                if hypervisor_macs is not None:
                    if port.get('mac_address') is None or port['mac_address'] not in hypervisor_macs:
                        # Can't use for this if the port is not given a MAC up front or
                        # the port's MAC isn't suitable
                        raise exception.PortNotUsable(
                            port_id=request.port_id,
                            instance=instance.uuid)
                        # yes, two ports can have the same MAC...

            else:
                # Only attachment by port works.
                raise NotImplementedError('Must attach NICs by port-id')
            if request.network_id:
                # Just in case the previous didn't pick that up:
                raise NotImplementedError("Gluon doesn't understand networks")
            if request.address:
                raise NotImplementedError("Gluon doesn't allow address setting")

        # Note: security groups are provided to the Nova VM, but not used because we never create
        # fresh ports, only use existing ones (that should already have security set).

        # Attempt to perform the port binding for all ports being attached to this VM
        zone = 'compute:%s' % instance.availability_zone
        bound_ports=[]
        try:
            for request in requested_networks:
                self._bind_port(request.port_id, zone, instance, request.pci_request_id)
                bound_ports.append(request.port_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._unbind_ports(context, bound_ports)

        LOG.info('attempting to update cached data following a bind: %d ports' % len(bound_ports))
        nw_info = self.get_instance_nw_info(
            context, instance,
            port_ids=bound_ports)
        # NOTE(danms): Only return info about ports we created in this run.
        # In the initial allocation case, this will be everything we created,
        # and in later runs will only be what was created that time. Thus,
        # this only affects the attach case, not the original use for this
        # method.
        return network_model.NetworkInfo([vif for vif in nw_info])

    def _bind_port(self, port_id, zone, instance, pci_request_id):
        """Populate gluon binding:profile.

        Populate it with SR-IOV related information
        """
        LOG.info('binding port %s' % port_id)
        pci_profile = None
        if pci_request_id:
            pci_dev = pci_manager.get_instance_pci_devs(
                instance, pci_request_id).pop()
            devspec = pci_whitelist.get_pci_device_devspec(pci_dev)
            pci_profile = {'pci_vendor_info': "%s:%s" % (pci_dev.vendor_id,
                                                         pci_dev.product_id),
                           'pci_slot': pci_dev.address,
                           'physical_network':
                               devspec.get_tags().get('physical_network')
                           }

        # These are used by Neutron extensions and could be used by other
        # things...
        flavor = instance.get_flavor()
        rxtx_factor = flavor.get('rxtx_factor')

        host = instance.get('host')

        self.client.bind(port_id, zone, instance.uuid, host, pci_profile=pci_profile, rxtx_factor=rxtx_factor)

    def deallocate_for_instance(self, context, instance, **kwargs):
        """Deallocate all network resources related to the instance."""
        LOG.debug('deallocate_for_instance()', instance=instance)
        # This used to get a list of ports matching this device from Neutron and free them all.
        # We could instead list the port IDs of the VIFs and unbound the ones we know about.
        #search_opts = {'device_id': instance.uuid}
        client = self.client
        #data = client.list_ports(owner=SERVICE_NAME, device=instance.uuid)
        ports = client.list_ports()
        port_ids = []
        for port in ports:
            # Reset device_id and device_owner for ports
            if port.get("device_id",'') == instance.uuid:
                port_ids.append(port.get("id"))
        self._unbind_ports(context, port_ids)

        # NOTE(arosen): This clears out the network_cache only if the instance
        # hasn't already been deleted. This is needed when an instance fails to
        # launch and is rescheduled onto another compute node. If the instance
        # has already been deleted this call does nothing.
        base_api.update_instance_cache_with_nw_info(self, context, instance,
                                                    network_model.NetworkInfo([]))

    def allocate_port_for_instance(self, context, instance, port_id,
                                   network_id=None, requested_ip=None):
        """Allocate a port for the instance."""
        requested_networks = objects.NetworkRequestList(
            objects=[objects.NetworkRequest(network_id=network_id,
                                            address=requested_ip,
                                            port_id=port_id,
                                            pci_request_id=None)])
        return self.allocate_for_instance(context, instance,
                                          requested_networks=requested_networks)

    def deallocate_port_for_instance(self, context, instance, port_id):
        """Remove a specified port from the instance.

        Return network information for the instance
        """
        self._unbind_ports(context, [port_id])
        return self.get_instance_nw_info(context, instance)

    def list_ports(self, context, **search_opts):
        """List ports for the client based on search options."""
        raise NotImplementedException()

    def show_port(self, context, port_id):
        """Return the port for the client given the port id."""
        raise NotImplementedException()

    def _get_instance_nw_info(self, context, instance,
                              port_ids=None):
        # NOTE(danms): This is an inner method intended to be called
        # by other code that updates instance nwinfo. It *must* be
        # called with the refresh_cache-%(instance_uuid) lock held!

        nw_info = self._build_network_info_model(context, instance,
                                                 port_ids)
        return network_model.NetworkInfo.hydrate(nw_info)

    def _gather_port_ids(self, context, instance,
                         port_ids=None):
        """Return an instance's complete list of port_ids."""

        ifaces = compute_utils.get_nw_info_for_instance(instance)
        # This code path is only done when refreshing the network_cache
        if port_ids is None:
            port_ids = [iface['id'] for iface in ifaces]
        else:
            # an interface was added/removed from instance.
            # Include existing interfaces so they are not removed from the db.
            port_ids = [iface['id'] for iface in ifaces] + port_ids

        return port_ids

    def _get_port_vnic_info(self, port_id):
        """Retrieve port vnic info

        Invoked with a valid port_id.
        Return vnic type and the attached physical network name.
        """
        phynet_name = None
        vnic_type = None
        client = self.client

        vnic_type, vnic_connection_ident = \
            client.get_vnic_details(port_id)
        return vnic_type, vnic_connection_ident

    def create_pci_requests_for_sriov_ports(self, context, pci_requests,
                                            requested_networks):
        """Check requested networks for any SR-IOV port request.

        Create a PCI request object for each SR-IOV port, and add it to the
        pci_requests object that contains a list of PCI request object.
        """
        if not requested_networks:
            return


        for request_net in requested_networks:
            phynet_name = None
            vnic_type = network_model.VNIC_TYPE_NORMAL

            if request_net.port_id:
                vnic_type, connection_ident = self._get_port_vnic_info(
                    request_net.port_id)
            pci_request_id = None
            if vnic_type != network_model.VNIC_TYPE_NORMAL:
                # all types other than 'normal' are PCI types?! TODO
                phynet_name = connection_iden['physical_network']
                request = objects.InstancePCIRequest(
                    count=1,
                    spec=[{pci_request.PCI_NET_TAG: phynet_name}],
                    request_id=str(uuid.uuid4()))
                pci_requests.requests.append(request)
                pci_request_id = request.request_id

            # Add pci_request_id into the requested network
            request_net.pci_request_id = pci_request_id

    def validate_networks(self, context, requested_networks, num_instances):
        """Validate that the tenant can use the requested connection types.

	Types are historically networks, then networks-but-sometimes ports
	when working with Neutron, but with Gluon they're all ports.  The
	function name carries the history, sorry.

	Also, despite the name, this function validates that there is quota
	enough to use the ports but not that there are rights.

        Return the number of instances than can be successfully allocated
        with the requested network configuration.
        """
        LOG.debug('validate_networks() for %s', requested_networks)

        if requested_networks is None or len(requested_networks) == 0:
            # Gluon doesn't support default 'all networks' mode, since it
            # doesn't know about networks
            raise exception.NotImplementedError("Must specify NICs with Gluon")


        # Otherwise, the only quota'd elements are ports, and we have
        # precreated ports, so we're all good and can create everything:
        return num_instances

    def migrate_instance_start(self, context, instance, migration):
        """Start to migrate the network of an instance."""
        # NOTE(wenjianhn): just pass to make migrate instance doesn't
        # raise for now.
        pass

    def migrate_instance_finish(self, context, instance, migration):
        """Finish migrating the network of an instance."""
        self._update_port_binding_for_instance(context, instance,
                                               migration['dest_compute'])

    def _build_network_info_model(self, context, instance,
                                  port_ids=None):
        """Return list of ordered VIFs attached to instance.

        :param context - request context.
        :param instance - instance we are returning network info for.
        :param port_ids - List of port_ids that are being attached to an
                          instance in order of attachment. If value is None
                          this value will be populated from the existing
                          cached value.
        """

        client = self.client
        current_gluon_ports = client.ports_by_device(instance.uuid)

        if port_ids is not None:
            LOG.info('updating gluon port list: %d ports supplied' % len(port_ids))
        nw_info_refresh = port_ids is None

        port_ids = self._gather_port_ids(
            context, instance, port_ids)
        nw_info = network_model.NetworkInfo()

        # Make a list of port dicts - these are what Gluon returns, an idealised form of what the backend offers up.
        # TODO a bulk op would help here.
        # NB - as a weirdness the port can be deleted from the backend without the compute service knowing.  It
        # will be removed from this datastructure if that has previously happened.
        LOG.info('updating gluon port list: %d ports found' % len(port_ids))
        gluon_port_list = [client.port(port_id) for port_id in port_ids if port_id]

        for port in gluon_port_list:
            LOG.info('updating gluon port list: %s' % port)
            # For the moment, absent more drastic changes to Nova's networking model,
            # we must have a network in this model.  Each port gets its own network.
            bridge = port.get('binding:details', {}).get('bridge')
            if bridge is None:
                bridge = 'br-int'
            network = network_model.Network(
                id=port.get('network_id', ''),
                bridge=bridge,
                injected=CONF.flat_injected,
                label=port.get('name',''),  # ?? TWH
                tenant_id=port.get('tenant_id','')
            )

            nw_info.append(network_model.VIF(
                id=port['id'],
                address=port.get('mac_address'),
                network=network,
                vnic_type=port.get('binding:vnic_type',
                                   network_model.VNIC_TYPE_NORMAL),
                type=port.get('binding:vif_type', 'ovs'),
                profile=port.get('binding:profile'),
                details=port.get('binding:vif_details'),
                ovs_interfaceid=port.get('binding:details', {}).get('ovs_interfaceid'),
                devname=port.get('devname', ''),
                active=port['status'],  # ?? TWH
                preserve_on_delete=True)) # Gluon ports: never deleted by Nova
        return nw_info

    def setup_instance_network_on_host(self, context, instance, host):
        """Setup network for specified instance on host."""
        self._update_port_binding_for_instance(context, instance, host)

    def cleanup_instance_network_on_host(self, context, instance, host):
        """Cleanup network for specified instance on host."""
        pass

    # TODO this hasn't been fully updated yet; used on migrations
    def _update_port_binding_for_instance(self, context, instance, host):
        client = self.client
        search_opts = {'device_id': instance.uuid,
                       'tenant_id': instance.project_id}
        data = client.list_ports(**search_opts)
        ports = data['ports']
        for p in ports:
            # If the host hasn't changed, like in the case of resizing to the
            # same host, there is nothing to do.
            if p.get('host') != host:
                try:
                    client.update_port(p['id'],
                                       {'port': {'host': host}})
                except Exception:
                    with excutils.save_and_reraise_exception():
                        LOG.exception(_LE("Unable to update host of port %s"),
                                      p['id'])
                        # ... and admit defeat, when the DB is in a state.  Typical.
