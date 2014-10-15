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

from neutron.openstack.common import log as logging
from neutron.services.firewall.drivers import fwaas_base
from neutron.services.firewall.agents.vyatta import vyatta_api
from neutron.services.firewall.agents.vyatta import vyatta_utils
import urllib

LOG = logging.getLogger(__name__)

class VyattaFirewallDriver(fwaas_base.FwaasDriverBase):
    
    def __init__(self):
        LOG.debug(_("Vyatta vRouter Fwaas:: Initializing fwaas driver"))
        

    def create_firewall(self, apply_list, firewall):
        LOG.debug(_('Vyatta vRouter Fwaas::Create_firewall (%s)'), firewall)
        
        return self.update_firewall(apply_list, firewall)


    def update_firewall(self, apply_list, firewall):
        LOG.debug(_('Vyatta vRouter Fwaas::Update_firewall (%s)'), firewall)
        
        if firewall['admin_state_up']:
            return self._update_firewall(apply_list, firewall)
        else:
            return self.apply_default_policy(apply_list, firewall)


    def delete_firewall(self, apply_list, firewall):
        LOG.debug(_('Vyatta vRouter Fwaas::Delete_firewall (%s)'), firewall)
        
        return self.apply_default_policy(apply_list, firewall)        


    def apply_default_policy(self, apply_list, firewall):
        LOG.debug(_('Vyatta vRouter Fwaas::apply_default_policy (%s)'), firewall)

        for ri in apply_list:
            self._delete_firewall(ri, firewall)

        return True


    def _update_firewall(self, apply_list, firewall):
        LOG.debug(_("Updating firewall (%s)"), firewall['id'])

        for ri in apply_list:
            self._delete_firewall(ri, firewall)
            self._setup_firewall(ri, firewall)

        return True
 
 
    def _setup_firewall(self, ri, fw):
                
        rest_api = vyatta_api.VyattaRestAPI()
        rest_api.connect(ri)
        
        fw_cmd_list=[]
                
        # Create firewall
        fw_name = vyatta_utils.get_firewall_name(ri, fw)
        fw_cmd_list.append(vyatta_api.SetCmd("firewall/name/{0}"
                                             .format(urllib.quote_plus(fw_name))))
        
        if fw.has_key('description') and len(fw['description']) > 0:
            fw_cmd_list.append(vyatta_api.SetCmd("firewall/name/{0}/description/{1}"
                                                 .format(urllib.quote_plus(fw_name),
                                                         urllib.quote_plus(fw['description']))))
        # Set firewall state policy
        fw_cmd_list.append(vyatta_api.SetCmd("firewall/state-policy/established/action/accept"))
        fw_cmd_list.append(vyatta_api.SetCmd("firewall/state-policy/related/action/accept"))
                
        # Create firewall rules
        rule_num = 0
        for rule in fw['firewall_rule_list']:
            if not rule['enabled']:
                continue
            if rule['ip_version'] == 4:
                rule_num += 1
                fw_cmd_list += self._set_firewall_rule(fw_name, rule_num, rule)
            else:
                LOG.warn(_("Unsupported IP version rule."))
        
        # Configure router zones
        zone_cmd_list = vyatta_utils.get_zone_cmds(rest_api, ri, fw_name)
        
        rest_api.configure_cmd_batch(fw_cmd_list + zone_cmd_list)
                
                
    def _delete_firewall(self, ri, fw):

        rest_api = vyatta_api.VyattaRestAPI()
        rest_api.connect(ri)
        
        cmd_list = []
        
        # Delete zones
        cmd_list.append(vyatta_api.DeleteCmd("zone-policy"))
        
        # Delete firewall
        fw_name = vyatta_utils.get_firewall_name(ri, fw)
        cmd_list.append(vyatta_api.DeleteCmd("firewall/name/{0}"
                                             .format(urllib.quote_plus(fw_name))))
        
        # Delete firewall state policy
        cmd_list.append(vyatta_api.DeleteCmd("firewall/state-policy"))
        
        rest_api.configure_cmd_batch(cmd_list)
        
        
    def _set_firewall_rule(self, fw_name, rule_num, rule):
        
        cmd_list = []
        
        
        if rule.has_key('description') and len(rule['description']) > 0:
            cmd_list.append(vyatta_api.SetCmd("firewall/name/{0}/rule/{1}/description/{2}"
                                                .format(urllib.quote_plus(fw_name),
                                                        rule_num,
                                                        urllib.quote_plus(rule['description']))))
        
        if rule.has_key('protocol') and rule['protocol'] is not None:
            cmd_list.append(vyatta_api.SetCmd("firewall/name/{0}/rule/{1}/protocol/{2}"
                                              .format(urllib.quote_plus(fw_name),
                                                      rule_num,
                                                      rule['protocol'] )))
        
        if rule.has_key('source_port') and rule['source_port'] is not None:
            cmd_list.append(vyatta_api.SetCmd("firewall/name/{0}/rule/{1}/source/port/{2}"
                                              .format(urllib.quote_plus(fw_name),
                                                      rule_num,
                                                      urllib.quote_plus(rule['source_port']))))

        if rule.has_key('destination_port') and rule['destination_port'] is not None:
            cmd_list.append(vyatta_api.SetCmd("firewall/name/{0}/rule/{1}/destination/port/{2}"
                                              .format(urllib.quote_plus(fw_name),
                                                      rule_num,
                                                      urllib.quote_plus(rule['destination_port']))))

        if rule.has_key('source_ip_address') and rule['source_ip_address'] is not None:
            cmd_list.append(vyatta_api.SetCmd("firewall/name/{0}/rule/{1}/source/address/{2}"
                                              .format(urllib.quote_plus(fw_name),
                                                      rule_num,
                                                      urllib.quote_plus(rule['source_ip_address']))))

        if rule.has_key('destination_ip_address') and rule['destination_ip_address'] is not None:
            cmd_list.append(vyatta_api.SetCmd("firewall/name/{0}/rule/{1}/destination/address/{2}"
                                                .format(urllib.quote_plus(fw_name),
                                                        rule_num,
                                                        urllib.quote_plus(rule['destination_ip_address']))))
            
        if rule.has_key('action'):
            if rule['action'] == 'allow':
                action = 'accept'
            else:
                action = 'drop'
            cmd_list.append(vyatta_api.SetCmd("firewall/name/{0}/rule/{1}/action/{2}"
                                              .format(urllib.quote_plus(fw_name),
                                                      rule_num,
                                                      action)))
        return cmd_list
