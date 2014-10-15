# vim: tabstop=4 shiftwidth=4 softtabstop=4
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
# @author: Karthik Natarajan (natarajk@brocade.com)
#

import eventlet

from oslo.config import cfg
from neutron.agent.common import config
from neutron.agent import l3_agent
from neutron.agent.linux import external_process
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.common import constants as l3_constants
from neutron.common import legacy
from neutron.common import topics
from neutron import context
from neutron.openstack.common import log as logging
from neutron.openstack.common import service
from neutron import service as neutron_service
from neutron.services.firewall.agents.l3reference import firewall_l3_agent
from neutron.services.firewall.agents.vyatta import vyatta_utils
from neutron.services.firewall.agents.vyatta import vyatta_api

LOG = logging.getLogger(__name__)

class VyattaL3NATAgent(l3_agent.L3NATAgent,
                        firewall_l3_agent.FWaaSL3AgentRpcCallback):
    
    def __init__(self, host, conf=None):
        LOG.debug(_('Vyatta vRouter NAT Agent: __init__'))
        super(VyattaL3NATAgent, self).__init__(host, conf)
        
    def _router_added(self, router_id, router):
        LOG.debug(_("Vyatta vRouter NAT Agent:_router_added: %s"), router_id)
        ri = l3_agent.RouterInfo(router_id, self.root_helper, False, router)
        self.router_info[router_id] = ri
        super(VyattaL3NATAgent, self).process_router_add(ri)

    def _router_removed(self, router_id):
        LOG.debug(_("Vyatta vRouter NAT Agent:_router_removed: %s"), router_id)
        ri = self.router_info[router_id]
        if ri:
            ri.router['gw_port'] = None
            ri.router[l3_constants.INTERFACE_KEY] = []
            ri.router[l3_constants.FLOATINGIP_KEY] = []
            self.process_router(ri)
            del self.router_info[router_id]

    def process_router(self, ri):
        rest_api = vyatta_api.VyattaRestAPI()
        rest_api.connect(ri)
        ctx = context.Context('', ri.router['tenant_id'])
        fw_list = self.fwplugin_rpc.get_firewalls_for_tenant(ctx)
        if len(fw_list) > 0:
            fw_name = vyatta_utils.get_firewall_name(ri, fw_list[0])
            zone_cmds = vyatta_utils.get_zone_cmds(rest_api, ri, fw_name)
            rest_api.configure_cmd_batch(zone_cmds)
                    
    def external_gateway_added(self, ri, ex_gw_port,
                               interface_name, internal_cidrs):
        LOG.debug(_("Vyatta vRouter NAT Agent:external_gateway_added: %s"), 
                    ri.router['id'])
        
        if not ip_lib.device_exists(interface_name,
                                    root_helper=self.root_helper,
                                    namespace=ri.ns_name()):
            self.driver.plug(ex_gw_port['network_id'],
                             ex_gw_port['id'], interface_name,
                             ex_gw_port['mac_address'],
                             bridge=self.conf.external_network_bridge,
                             namespace=ri.ns_name(),
                             prefix=l3_agent.EXTERNAL_DEV_PREFIX)
        self.driver.init_l3(interface_name, [ex_gw_port['ip_cidr']],
                            namespace=ri.ns_name())
    
    def _create_router_namespace(self, ri):
        return
    
    def _destroy_router_namespaces(self, only_router_id=None):
        return

    def _destroy_router_namespace(self, namespace):
        return

    def _spawn_metadata_proxy(self, router_info):
        return

    def _destroy_metadata_proxy(self, router_info):
        return        
                
    def _handle_router_snat_rules(self, ri, ex_gw_port, internal_cidrs,
                                  interface_name, action):
        return

    def _send_gratuitous_arp_packet(self, ri, interface_name, ip_address):
        return

    def _update_routing_table(self, ri, operation, route):
        return


class VyattaL3NATAgentWithStateReport(VyattaL3NATAgent,
                                      l3_agent.L3NATAgentWithStateReport):
    pass


def main():
    eventlet.monkey_patch()
    conf = cfg.CONF
    conf.register_opts(VyattaL3NATAgent.OPTS)
    config.register_interface_driver_opts_helper(conf)
    config.register_use_namespaces_opts_helper(conf)
    config.register_agent_state_opts_helper(conf)
    config.register_root_helper(conf)
    conf.register_opts(interface.OPTS)
    conf.register_opts(external_process.OPTS)
    conf(project='neutron')
    config.setup_logging(conf)
    legacy.modernize_quantum_config(conf)
    server = neutron_service.Service.create(
        binary='vyatta-l3-agent',
        topic=topics.L3_AGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager='neutron.services.firewall.agents.vyatta.vyatta_router.VyattaL3NATAgentWithStateReport')
    service.launch(server).wait()
    
if __name__ == "__main__":
    main()
