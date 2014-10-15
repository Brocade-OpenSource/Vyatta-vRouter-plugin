# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation.
# All Rights Reserved.
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

# Author:
# Karthik Natarajan (natarajk@brocade.com)

import netaddr

from sqlalchemy.orm import exc

from neutron.api.v2 import attributes
from neutron.openstack.common import log as logging
from neutron.common import constants as l3_constants
from neutron.common import exceptions as q_exc
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.extensions import l3
from neutron.openstack.common import excutils
from neutron.openstack.common.notifier import api as notifier_api
from neutron.services.l3_router import l3_router_plugin as l3_plugin
from neutron.plugins.common import constants

from neutron.plugins.brocade.vyatta import vrouter_driver

LOG = logging.getLogger(__name__)

""" Vyatta VRouter L3 plugin"""


class VyattaVRouterPlugin(l3_plugin.L3RouterPlugin):

    def __init__(self):
        super(VyattaVRouterPlugin, self).__init__()
        self.driver = vrouter_driver.VyattaVRouterDriver()

    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        """Returns string description of the plugin."""
        return ("Vyatta Router Service Plugin for basic L3 forwarding"
                " between (L2) Neutron networks and access to external"
                " networks via a NAT gateway.")

    def create_router(self, context, router):
        LOG.debug(_("Vyatta vRouter Plugin::Create router"))
        r = router['router']
        router_id = self.driver.create_router(context)
        if router_id is None:
            raise q_exc.BadRequest(
                resource='router',
                msg=_('Vyatta vRouter creation failed'))
        has_gw_info = False
        if l3.EXTERNAL_GW_INFO in r:
            has_gw_info = True
            gw_info = r[l3.EXTERNAL_GW_INFO]
            del r[l3.EXTERNAL_GW_INFO]
        tenant_id = self._get_tenant_id_for_create(context, r)
        with context.session.begin(subtransactions=True):
            router_db = l3_db.Router(id=router_id,
                                     tenant_id=tenant_id,
                                     name=r['name'],
                                     admin_state_up=r['admin_state_up'],
                                     status="ACTIVE")
            context.session.add(router_db)
            router_dict = self._make_router_dict(router_db)
            self.driver.init_router(context, router_dict)

        if has_gw_info:
            self._update_router_gw_info(context, router_db['id'], gw_info)
        return router_dict

    def update_router(self, context, router_id, router):
        LOG.debug(_("Vyatta vRouter Plugin::Update router"))
        r = router['router']
        has_gw_info = False
        if l3.EXTERNAL_GW_INFO in r:
            has_gw_info = True
            gw_info = r[l3.EXTERNAL_GW_INFO]
            del r[l3.EXTERNAL_GW_INFO]
        if has_gw_info:
            self._update_router_gw_info(context, router_id, gw_info)
        with context.session.begin(subtransactions=True):
            router_db = self._get_router(context, router_id)
            # Ensure we actually have something to update
            if r.keys():
                router_db.update(r)
        self.l3_rpc_notifier.routers_updated(
            context, [router_db['id']])
        return self._make_router_dict(router_db)

    def get_router(self, context, router_id, fields=None):
        LOG.debug(_("Vyatta vRouter Plugin::Get router"))
        router = self._get_router(context, router_id)
        return self._make_router_dict(router, fields)

    def delete_router(self, context, router_id):
        LOG.debug(_("Vyatta vRouter Plugin::Delete router"))
        with context.session.begin(subtransactions=True):
            router = self._get_router(context, router_id)

            # Ensure that the router is not used
            fips = self.get_floatingips_count(context,
                                              filters={'router_id':
                                                       [router_id]})
            if fips:
                raise l3.RouterInUse(router_id=router_id)

            device_filter = {
                'device_id': [router_id],
                'device_owner': [l3_constants.DEVICE_OWNER_ROUTER_INTF]
            }
            ports = self._core_plugin.get_ports_count(context.elevated(),
                                                      filters=device_filter)
            if ports:
                raise l3.RouterInUse(router_id=router_id)

            # delete any gw port
            device_filter = {
                'device_id': [router_id],
                'device_owner': [l3_constants.DEVICE_OWNER_ROUTER_GW]
            }
            ports = self._core_plugin.get_ports(context.elevated(),
                                                filters=device_filter)
            if ports:
                port = ports[0]
                self._delete_router_port(context, router_id, port)

            self.driver.delete_router(context, router_id)
            context.session.delete(router)

        self.l3_rpc_notifier.router_deleted(context, router_id)

    def get_routers(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None, page_reverse=False):
        LOG.debug(_("Vyatta vRouter Plugin::Get Routers"))
        marker_obj = self._get_marker_obj(context, 'router', limit, marker)
        return self._get_collection(context, l3_db.Router,
                                    self._make_router_dict, filters=filters,
                                    fields=fields, sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def add_router_interface(self, context, router_id, interface_info):
        LOG.debug(_("Vyatta vRouter Plugin::Add Router Interface"))
        if not interface_info:
            msg = _("Either subnet_id or port_id must be specified")
            raise q_exc.BadRequest(resource='router', msg=msg)

        if 'port_id' in interface_info:
            # make sure port update is committed
            with context.session.begin(subtransactions=True):
                if 'subnet_id' in interface_info:
                    msg = _("Cannot specify both subnet-id and port-id")
                    raise q_exc.BadRequest(resource='router', msg=msg)

                port = self._core_plugin._get_port(context.elevated(),
                                                   interface_info['port_id'])
                if port['device_id']:
                    raise q_exc.PortInUse(net_id=port['network_id'],
                                          port_id=port['id'],
                                          device_id=port['device_id'])
                fixed_ips = [ip for ip in port['fixed_ips']]
                if len(fixed_ips) != 1:
                    msg = _('Router port must have exactly one fixed IP')
                    raise q_exc.BadRequest(resource='router', msg=msg)
                subnet_id = fixed_ips[0]['subnet_id']
                subnet = self._core_plugin._get_subnet(context.elevated(),
                                                       subnet_id)
                self._check_for_dup_router_subnet(context, router_id,
                                                  port['network_id'],
                                                  subnet['id'],
                                                  subnet['cidr'])
            port_created = False
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            subnet = self._core_plugin._get_subnet(context.elevated(),
                                                   subnet_id)
            # Ensure the subnet has a gateway
            if not subnet['gateway_ip']:
                msg = _('Subnet for router interface must have a gateway IP')
                raise q_exc.BadRequest(resource='router', msg=msg)
            self._check_for_dup_router_subnet(context, router_id,
                                              subnet['network_id'],
                                              subnet_id,
                                              subnet['cidr'])
            fixed_ip = {'ip_address': subnet['gateway_ip'],
                        'subnet_id': subnet['id']}
            port = self._core_plugin.create_port(context.elevated(), {
                'port':
                    {'tenant_id': subnet['tenant_id'],
                     'network_id': subnet['network_id'],
                     'fixed_ips': [fixed_ip],
                     'mac_address': attributes.ATTR_NOT_SPECIFIED,
                     'admin_state_up': True,
                     'device_id': '',
                     'device_owner': '',
                     'name': ''}})
            port_created = True

        try:
            self._attach_port(context, router_id, port)
        except Exception:
            with excutils.save_and_reraise_exception():
                if port_created:
                    try:
                        self._core_plugin.delete_port(context.elevated(),
                                                      port['id'])
                    except Exception:
                        LOG.exception(_('Failed to delete previously created '
                                        'port for Vyatta vRouter.'))

        self.l3_rpc_notifier.routers_updated(
            context, [router_id], 'add_router_interface')

        info = {'id': router_id,
                'tenant_id': subnet['tenant_id'],
                'port_id': port['id'],
                'subnet_id': port['fixed_ips'][0]['subnet_id']}
        notifier_api.notify(
            context, notifier_api.publisher_id('network'),
            'router.interface.create',
            notifier_api.CONF.default_notification_level,
            {'router.interface': info})
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        LOG.debug(_("Vyatta vRouter Plugin::Remove Router Interface"))
        if not interface_info:
            msg = _("Either subnet_id or port_id must be specified")
            raise q_exc.BadRequest(resource='router', msg=msg)

        if 'port_id' in interface_info:
            port_id = interface_info['port_id']
            port_db = self._core_plugin._get_port(context.elevated(), port_id)
            if not (port_db['device_owner'] ==
                    l3_constants.DEVICE_OWNER_ROUTER_INTF and
                    port_db['device_id'] == router_id):
                raise l3.RouterInterfaceNotFound(router_id=router_id,
                                                 port_id=port_id)
            if 'subnet_id' in interface_info:
                port_subnet_id = port_db['fixed_ips'][0]['subnet_id']
                if port_subnet_id != interface_info['subnet_id']:
                    raise q_exc.SubnetMismatchForPort(
                        port_id=port_id,
                        subnet_id=interface_info['subnet_id'])
            subnet_id = port_db['fixed_ips'][0]['subnet_id']
            subnet = self._core_plugin._get_subnet(context.elevated(),
                                                   subnet_id)
            self._confirm_router_interface_not_in_use(
                context, router_id, subnet_id)
            port = port_db
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            self._confirm_router_interface_not_in_use(context, router_id,
                                                      subnet_id)
            subnet = self._core_plugin._get_subnet(context.elevated(),
                                                   subnet_id)
            found = False
            try:
                rport_qry = context.session.query(models_v2.Port)
                ports = rport_qry.filter_by(
                    device_id=router_id,
                    device_owner=l3_constants.DEVICE_OWNER_ROUTER_INTF,
                    network_id=subnet['network_id'])

                for p in ports:
                    if p['fixed_ips'][0]['subnet_id'] == subnet_id:
                        port = p
                        found = True
                        break
            except exc.NoResultFound:
                pass

            if not found:
                raise l3.RouterInterfaceNotFoundForSubnet(router_id=router_id,
                                                          subnet_id=subnet_id)

        self._delete_router_port(context, router_id, port)

        self.l3_rpc_notifier.routers_updated(
            context, [router_id], 'remove_router_interface')

        info = {'id': router_id,
                'tenant_id': subnet['tenant_id'],
                'port_id': port['id'],
                'subnet_id': subnet_id}
        notifier_api.notify(context,
                            notifier_api.publisher_id('network'),
                            'router.interface.delete',
                            notifier_api.CONF.default_notification_level,
                            {'router.interface': info})
        return info

    def _get_router(self, context, router_id):
        LOG.debug(_("Vyatta vRouter Plugin::Get router by id"))
        try:
            router = self._get_by_id(context, l3_db.Router, router_id)
        except exc.NoResultFound:
            raise l3.RouterNotFound(router_id=router_id)
        return router

    def _check_for_dup_router_subnet(self, context, router_id,
                                     network_id, subnet_id, subnet_cidr):
        LOG.debug(
            _("Vyatta vRouter Plugin::Check for duplicate router subnet"))
        try:
            rport_qry = context.session.query(models_v2.Port)
            rports = rport_qry.filter_by(device_id=router_id)
            # its possible these ports on on the same network, but
            # different subnet
            new_ipnet = netaddr.IPNetwork(subnet_cidr)
            for p in rports:
                for ip in p['fixed_ips']:
                    if ip['subnet_id'] == subnet_id:
                        msg = (_("Router already has a port on subnet %s")
                               % subnet_id)
                        raise q_exc.BadRequest(resource='router', msg=msg)
                    sub_id = ip['subnet_id']
                    cidr = self._core_plugin._get_subnet(context.elevated(),
                                                         sub_id)['cidr']
                    ipnet = netaddr.IPNetwork(cidr)
                    match1 = netaddr.all_matching_cidrs(new_ipnet, [cidr])
                    match2 = netaddr.all_matching_cidrs(ipnet, [subnet_cidr])
                    if match1 or match2:
                        data = {'subnet_cidr': subnet_cidr,
                                'subnet_id': subnet_id,
                                'cidr': cidr,
                                'sub_id': sub_id}
                        msg = (_("Cidr %(subnet_cidr)s of subnet "
                                 "%(subnet_id)s overlaps with cidr %(cidr)s "
                                 "of subnet %(sub_id)s") % data)
                        raise q_exc.BadRequest(resource='router', msg=msg)
        except exc.NoResultFound:
            pass

    def _get_interface_infos(self, context, port):
        LOG.debug(_("Vyatta vRouter Plugin::Get interface infos"))
        mac_address = port['mac_address']
        interface_infos = []
        for fip in port['fixed_ips']:
            try:
                subnet = self._core_plugin._get_subnet(context.elevated(),
                                                       fip['subnet_id'])
                ipnet = netaddr.IPNetwork(subnet.cidr)
                interface_infos.append({
                    'mac_address': mac_address,
                    'ip_address': '{0}/{1}'.format(fip['ip_address'],
                                                   ipnet.prefixlen),
                    'gateway_ip': subnet.gateway_ip
                })
            except q_exc.SubnetNotFound:
                pass
        return interface_infos

    def _delete_router_port(self, context, router_id, port, external_gw=False):
        # Get instance, deconfigure interface and detach port from it. To do
        # this need to change port owner back to that instance.
        LOG.debug(_("Vyatta vRouter Plugin::Delete router port"))

        self.driver.deconfigure_interface(
            context, router_id, self._get_interface_infos(context.elevated(),
                                                          port))
        self._core_plugin.update_port(context.elevated(), port['id'],
                                      {'port': {'device_owner': '',
                                                'device_id': router_id}})
        self.driver.detach_interface(context, router_id, port['id'])

    def _attach_port(self, context, router_id, port, external_gw=False):
        LOG.debug(_("Vyatta vRouter Plugin::Attach port"))
        # Attach interface
        self.driver.attach_interface(context, router_id, port['id'])
        context.session.expunge(self._core_plugin._get_port(context.elevated(),
                                                            port['id']))

        if external_gw:
            self.driver.configure_gateway(
                context, router_id, self._get_interface_infos(context, port))
        else:
            self.driver.configure_interface(
                context, router_id, self._get_interface_infos(context, port))

        if external_gw:
            device_owner = l3_constants.DEVICE_OWNER_ROUTER_GW
        else:
            device_owner = l3_constants.DEVICE_OWNER_ROUTER_INTF
        self._core_plugin.update_port(context.elevated(), port['id'],
                                      {'port': {'device_owner': device_owner,
                                                'device_id': router_id}})

    def _update_router_gw_info(self, context, router_id, info, router=None):
        LOG.debug(_("Vyatta vRouter Plugin::Update router gateway info"))
        # TODO(salvatore-orlando): guarantee atomic behavior also across
        # operations that span beyond the model classes handled by this
        # class (e.g.: delete_port)
        router = router or self._get_router(context, router_id)
        gw_port = router.gw_port
        # network_id attribute is required by API, so it must be present
        network_id = info['network_id'] if info else None
        ext_net_tenant_id = ''
        if network_id:
            network_db = self._core_plugin._get_network(context.elevated(),
                                                        network_id)
            ext_net_tenant_id = network_db.tenant_id
            if not network_db.external:
                msg = _("Network %s is not a valid external "
                        "network") % network_id
                raise q_exc.BadRequest(resource='router', msg=msg)

        # figure out if we need to delete existing port
        if gw_port and gw_port['network_id'] != network_id:
            fip_count = self.get_floatingips_count(context.elevated(),
                                                   {'router_id': [router_id]})
            if fip_count:
                raise l3.RouterExternalGatewayInUseByFloatingIp(
                    router_id=router_id, net_id=gw_port['network_id'])
            if gw_port and gw_port['network_id'] != network_id:
                try:
                    self.driver.clear_gateway(
                        context, router_id, self._get_interface_infos(
                                                 context.elevated(),
                                                 gw_port))
                    self._delete_router_port(
                        context, router_id, gw_port, external_gw=True)
                    with context.session.begin(subtransactions=True):
                        router.gw_port = None
                        context.session.add(router)
                except Exception as ex:
                    LOG.exception(_("Exception while attaching port : %s")
                                  % ex)
                    raise ex

        if network_id is not None and (gw_port is None or
                                       gw_port['network_id'] != network_id):
            subnets = self._core_plugin._get_subnets_by_network(
                                            context.elevated(), network_id)
            for subnet in subnets:
                self._check_for_dup_router_subnet(context, router_id,
                                                  network_id, subnet['id'],
                                                  subnet['cidr'])
            gw_port = self._core_plugin.create_port(context.elevated(), {
                'port': {'tenant_id': ext_net_tenant_id,
                         'network_id': network_id,
                         'mac_address': attributes.ATTR_NOT_SPECIFIED,
                         'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                         'device_owner': '',
                         'device_id': '',
                         'admin_state_up': True,
                         'name': ''}})

            if not gw_port['fixed_ips']:
                self._core_plugin.delete_port(context.elevated(),
                                              gw_port['id'],
                                              l3_port_check=False)
                msg = (_('No IPs available for external network %s') %
                       network_id)
                raise q_exc.BadRequest(resource='router', msg=msg)

            with context.session.begin(subtransactions=True):
                router.gw_port = self._core_plugin._get_port(
                                                    context.elevated(),
                                                    gw_port['id'])
                context.session.add(router)
            try:
                self._attach_port(context, router_id, gw_port,
                                  external_gw=True)
            except Exception as ex:
                LOG.exception(_("Exception while attaching port : %s") % ex)
                with excutils.save_and_reraise_exception():
                    try:
                        with context.session.begin(subtransactions=True):
                            router.gw_port = None
                            context.session.add(router)
                            self._core_plugin.delete_port(context.elevated(),
                                                          gw_port['id'])
                    except Exception:
                        LOG.exception(_('Failed to roll back changes to '
                                        'Vyatta vRouter after external '
                                        'gateway assignment.'))

    def _confirm_router_interface_not_in_use(self, context, router_id,
                                             subnet_id):
        LOG.debug(
            _("Vyatta vRouter Plugin::Confirming router interface not in use"))
        subnet_db = self._core_plugin._get_subnet(context.elevated(),
                                                  subnet_id)
        subnet_cidr = netaddr.IPNetwork(subnet_db['cidr'])
        fip_qry = context.session.query(l3_db.FloatingIP)
        for fip_db in fip_qry.filter_by(router_id=router_id):
            if netaddr.IPAddress(fip_db['fixed_ip_address']) in subnet_cidr:
                raise l3.RouterInterfaceInUseByFloatingIP(
                    router_id=router_id, subnet_id=subnet_id)

    def get_routers_count(self, context, filters=None):
        LOG.debug(_("Vyatta vRouter Plugin::Get routers count"))
        return self._get_collection_count(context, l3_db.Router,
                                          filters=filters)

    def create_floatingip(self, context, floatingip):
        LOG.debug(_("Vyatta vRouter Plugin::Create floating ip"))
        floatingip_dict = super(VyattaVRouterPlugin, self).create_floatingip(
                                                              context,
                                                              floatingip)
        router_id = floatingip_dict['router_id']
        if router_id:
            self.associate_floatingip(context, router_id, floatingip_dict)
        return floatingip_dict

    def associate_floatingip(self, context, router_id, floatingip):
        LOG.debug(_("Vyatta vRouter Plugin::Associate floating ip"))
        fixed_ip = floatingip['fixed_ip_address']
        floating_ip = floatingip['floating_ip_address']
        if router_id:
            self.driver.assign_floating_ip(
                context, router_id, floating_ip, fixed_ip)

    def update_floatingip(self, context, floatingip_id, floatingip):
        LOG.debug(_("Vyatta vRouter Plugin::Update floating ip"))
        fip = floatingip['floatingip']
        with context.session.begin(subtransactions=True):
            floatingip_db = self._get_floatingip(context, floatingip_id)
            old_floatingip = self._make_floatingip_dict(floatingip_db)
            fip['tenant_id'] = floatingip_db['tenant_id']
            fip['id'] = floatingip_id
            fip_port_id = floatingip_db['floating_port_id']
            before_router_id = floatingip_db['router_id']
            self._update_fip_assoc(context, fip, floatingip_db,
                                   self._core_plugin.get_port(
                                       context.elevated(), fip_port_id))
        if before_router_id:
            self.disassociate_floatingip(
                context, before_router_id, old_floatingip)

        router_id = floatingip_db['router_id']
        if router_id:
            self.associate_floatingip(context, router_id, floatingip_db)
        return self._make_floatingip_dict(floatingip_db)

    def delete_floatingip(self, context, floatingip_id):
        LOG.debug(_("Vyatta vRouter Plugin::Delete floating ip"))
        floatingip_dict = self._get_floatingip(context, floatingip_id)
        router_id = floatingip_dict['router_id']
        if router_id:
            self.disassociate_floatingip(context, router_id, floatingip_dict)
        super(VyattaVRouterPlugin, self).delete_floatingip(
            context, floatingip_id)

    def disassociate_floatingip(self, context, router_id, floatingip):
        LOG.debug(_("Vyatta vRouter Plugin::Disassociate floating ip"))
        fixed_ip = floatingip['fixed_ip_address']
        floating_ip = floatingip['floating_ip_address']
        if router_id:
            self.driver.unassign_floating_ip(
                context, router_id, floating_ip, fixed_ip)
