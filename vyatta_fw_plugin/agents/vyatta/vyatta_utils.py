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
# @author: Karthik Natarajan, natarajk@brocade.com

import urllib
from neutron.openstack.common import log as logging
from neutron.common import constants as l3_constants
from neutron.services.firewall.agents.vyatta import vyatta_api

TRUST_ZONE = 'Internal_Trust'
UNTRUST_ZONE = 'External_Untrust'

LOG = logging.getLogger(__name__)

def get_firewall_name(ri, fw):
    return fw['name']


def get_trusted_zone_name(ri):
    return TRUST_ZONE


def get_untrusted_zone_name(ri):
    return UNTRUST_ZONE


def get_zone_cmds(rest_api, ri, fw_name):
                
    cmd_list=[]
    
    # Delete the zone policies
    cmd_list.append(vyatta_api.DeleteCmd("zone-policy"))    
    
    # Configure trusted zone        
    trusted_zone_name = None    
    # Add internal ports to trusted zone           
    if ri.router.has_key(l3_constants.INTERFACE_KEY):
        trusted_zone_name = urllib.quote_plus(get_trusted_zone_name(ri))       
        for port in ri.router[l3_constants.INTERFACE_KEY]:
            eth_if_id = rest_api.get_ethernet_if_id(port['mac_address'])
            cmd_list.append(vyatta_api.SetCmd( 
                                        "zone-policy/zone/{0}/interface/{1}"
                                         .format(trusted_zone_name,
                                                 eth_if_id)))
    # Configure untrusted zone            
    untrusted_zone_name = get_untrusted_zone_name(ri)
    if untrusted_zone_name is not None:
        # Add external ports to untrusted zone                           
        if ri.router.has_key('gw_port'):       
            gw_port = ri.router['gw_port']         
            eth_if_id = rest_api.get_ethernet_if_id(gw_port['mac_address'])
            cmd_list.append(vyatta_api.SetCmd(
                                        "zone-policy/zone/{0}/interface/{1}"
                                         .format(untrusted_zone_name,
                                                 eth_if_id)))   
            
            if trusted_zone_name is not None:
                # Associate firewall to zone            
                cmd_list.append(vyatta_api.SetCmd(
                                            "zone-policy/zone/{0}/from/{1}/firewall/name/{2}"
                                            .format(trusted_zone_name,
                                                    untrusted_zone_name,
                                                    urllib.quote_plus(fw_name))))       
                
                cmd_list.append(vyatta_api.SetCmd(                                 
                                            "zone-policy/zone/{0}/from/{1}/firewall/name/{2}"
                                            .format(untrusted_zone_name,
                                                    trusted_zone_name,
                                                    urllib.quote_plus(fw_name))))
                    
    return cmd_list
