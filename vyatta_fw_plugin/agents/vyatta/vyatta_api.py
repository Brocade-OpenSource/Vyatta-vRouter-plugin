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

import base64
import httplib
import socket
import re
from oslo.config import cfg
from sqlalchemy.orm import exc as orm_exception
from neutron.common import exceptions
from novaclient.v1_1 import client as novaclient
from neutron.openstack.common import log as logging
from neutron import context
from neutron.db import models_v2

cfg.CONF.register_opts([
    cfg.StrOpt('tenant_admin_name', help=_('Name of tenant admin user.')),
    cfg.StrOpt('tenant_admin_password', help=_('Tenant admin password.')),
    cfg.StrOpt('tenant_id',
               help=_('UUID of tenant that holds Vyatta vRouter instances.')),
    cfg.StrOpt('keystone_url', help=_('Keystone URL.')),
    cfg.StrOpt('image_id',
               help=_('Nova image id for instances of Vyatta vRouter.')),
    cfg.StrOpt('flavor',
               help=_('Nova VM flavor for instances of Vyatta vRouter.')),
    cfg.StrOpt('management_network_id',
               help=_('UUID of Vyatta vRouter management network.')),
    cfg.StrOpt('vrouter_credentials', default="vyatta:vyatta",              
               help=_('Vyatta vRouter login credentials')),                        
    cfg.IntOpt('nova_poll_interval', default=5,
               help=_('Number of seconds between consecutive Nova queries '
                      'when waiting for router instance status change.')),
    cfg.IntOpt('nova_spawn_timeout', default=300,
               help=_('Number of seconds to wait for Nova to activate '
                      'instance before setting resource to error state.')),
    cfg.IntOpt('vrouter_poll_interval', default=5,
               help=_('Number of seconds between consecutive Vyatta vRouter '
                      'queries when waiting for router instance boot.')),
    cfg.IntOpt('vrouter_boot_timeout', default=300,
               help=_('Number of seconds to wait for Vyatta vRouter to boot '
                      'before setting resource to error state.')),
], "VROUTER")

LOG = logging.getLogger(__name__)

class VRouterConnectFailure(exceptions.NeutronException):
    """Couldn't connect to instance."""
    message = _("Couldn't connect to Vyatta vRouter [%(ip_address)s].")    


class VRouterOperationError(exceptions.NeutronException):
    """Internal Vyatta vRouter exception."""
    message = _("Internal Vyatta vRouter exception [%(ip_address)s]:"
                "%(reason)s.")

class InvalidVRouterInstance(exceptions.NeutronException):
    """Couldn't find the vrouter instance mapping."""
    message = _("Couldn't find Vyatta vRouter instance %(router_id)s.")

    
class InvalidInstanceConfiguration(exceptions.NeutronException):
    message = _("Invalid Vyatta vRouter configuration: %(cause)s.")


class UserCmd(object):
    
    def __init__(self, cmd_type, cmd):
        self.cmd_type = cmd_type
        self.cmd = cmd

class SetCmd(UserCmd):
    
    def __init__(self, cmd):        
        super(SetCmd, self).__init__("set", cmd)  
        
class DeleteCmd(UserCmd):
    
    def __init__(self, cmd):        
        super(DeleteCmd, self).__init__("delete", cmd)  
            
class VyattaRestAPI(object):

    # HTTP response
    class HTTPResponse:
        
        def __init__(self, status, reason, headers, data):
            self.status = status
            self.reason = reason
            self.headers = headers
            self.data = data
            
        def get_status(self):
            return self.status
        
        def get_reason(self):
            return self.reason
        
        def get_header(self, key):
            return self.headers.getheader(key, None)
        
        def get_data(self):
            return self.data
    
            
    def __init__(self):
        LOG.debug(_('VyattaRestAPI: started'))


    def connect(self, ri):        
        self.address = self._get_router_address(ri.router['id'])                
        if self.address == None:
            raise Exception(_("Unable to find management ip for router %s"), 
                              ri.router['id'])
                        
    """ Used to get nova client handle """
    def _get_nova_client(self):
        LOG.debug(_("Vyatta vRouter Driver::Get Nova client"))
        # TODO: cache keystone token
        return novaclient.Client(
            cfg.CONF.VROUTER.tenant_admin_name,
            cfg.CONF.VROUTER.tenant_admin_password,
            None,
            cfg.CONF.VROUTER.keystone_url,
            service_type="compute",
            tenant_id=cfg.CONF.VROUTER.tenant_id)

    def _get_router_address(self, router_id):
        LOG.debug(_("Vyatta API::Get router driver"))
        nova_client = self._get_nova_client()
        try:
            vrouter_instance = nova_client.servers.get(router_id)
        except Exception as ex:
            LOG.error(_("Unable to find Vyatta vRouter instance %s" % ex))
            raise InvalidVRouterInstance(router_id=router_id)

        try:
            query = context.get_admin_context().session.query(models_v2.Network)
            network = query.filter(models_v2.Network.id == 
                                   cfg.CONF.VROUTER.management_network_id).one()
        except orm_exception.NoResultFound as ex:
            LOG.error(_("Unable to find Vyatta vRouter management network %s" % ex))
            raise InvalidInstanceConfiguration(
                  cause='Unable to find management network')
                   
        LOG.debug(_("Vyatta vRouter Management network: %s") % network['name'])
        address_map = vrouter_instance.addresses[network['name']]
        if address_map is None:
            raise InvalidVRouterInstance(router_id=router_id)
        address = address_map[0]["addr"]
        return address
            

    def configure_cmd(self, cmd_type, cmd):

        """
            Executes the given configuration command
            Commits and Saves the configuration changes to the startup config
        """
        self.configure_cmd_list(cmd_type, [cmd])


    def configure_cmd_list(self, cmd_type, cmd_list):
        
        user_cmd_list = []
        for cmd in cmd_list:
            user_cmd = self.UserCmd(cmd_type, cmd)
            user_cmd_list.append(user_cmd)
            
        self.configure_cmd_batch(user_cmd_list)             
            
    
    def configure_cmd_batch(self, user_cmd_list):

        """
            Executes the given configuration command list
            Commits and Saves the configuration changes to the startup config
        """     
        response = self._rest_call("POST", "/rest/conf")
        self._check_response(response)
                        
        config_url = response.get_header('location')
        if config_url is None:
            raise VRouterOperationError(ip_address=self.address,
                                        reason='REST API configuration URL is null')              
        config_url = "/" + config_url 
        for user_cmd in user_cmd_list:
            config_cmd = '{0}/{1}/{2}'.format(config_url, 
                                              user_cmd.cmd_type, user_cmd.cmd)
            LOG.debug(_("Vyatta vRouter REST API: Config command %s"), config_cmd)
            response = self._rest_call("PUT", config_cmd)
            self._check_response(response, config_url)
                           
        response = self._rest_call("POST", config_url + "/commit")
        self._check_response(response, config_url)
        
        response = self._rest_call("POST", config_url + "/save")
        self._check_response(response, config_url)

        response = self._rest_call("DELETE", config_url) 
        self._check_response(response)


    def execute_cli_cmd(self, cli_cmd):   
    
        """
            Executes any given CLI command using REST API
        """
        custom_headers = {'shell-command': cli_cmd}
        response = self._rest_call("GET", "/rest/app/command", custom_headers)
        self._check_response(response)
        return response.get_data()


    def get_ethernet_if_id(self, mac_address):
        
        """
            Uses show command output to find the ethernet interface 
            for the given mac address. Converts to lower case before comparison
        """                    
        cli_output = '\n\n' + self.execute_cli_cmd('sudo ifconfig -a')
        
        eth_interfaces = {}
        given_mac_address = mac_address.lower()
        
        for paragraph in cli_output.split('\n\n'):    
            # Regular expression match
            match_line = re.compile("(eth\d+).*HWaddr ([^ ]+)")
            result = match_line.match(paragraph)    
            if result is not None:
                eth_if_id = result.group(1)
                cli_mac_addr = result.group(2).lower()
                eth_interfaces[cli_mac_addr] = eth_if_id
        
        if (not eth_interfaces.has_key(given_mac_address)):
            raise VRouterOperationError(ip_address=self.address, 
                  reason='Ethernet interface with Mac-address {0} does not exist'.
                  format(given_mac_address))
            
        return eth_interfaces[given_mac_address]
        

            
    def _check_response(self, response, config_url=None):

        if response.status not in (200, 201):
            LOG.error(_('Vyatta vRouter REST API: Response Status : '
                        '%(status)s Reason: %(reason)s') %
                        {'status': response.status, 
                        'reason': response.reason})

            if config_url is not None:   
                self._rest_call("DELETE", config_url)

            raise VRouterOperationError(ip_address=self.address,
                                        reason=response.reason)
 
    def _rest_call(self, method, url, custom_headers=None):
        headers = {}
        auth = base64.b64encode(cfg.CONF.VROUTER.vrouter_credentials)
        headers['Authorization'] = 'Basic ' + auth
        headers['Accept'] = 'application/json'
        headers['Content-Length'] = 0
        
        if custom_headers is not None:
            for key, val in custom_headers.iteritems():
                headers[key] = val
            
        conn = httplib.HTTPSConnection(self.address)
        if conn is None:
            LOG.error(_('Vyatta vRouter REST API: Could not establish HTTP connection.'))
            raise VRouterConnectFailure(ip_address=self.address)

        try:
            conn.request(method, url, headers=headers)
            response = conn.getresponse()
            http_response = self.HTTPResponse(response.status,
                                              response.reason,
                                              response.msg,
                                              response.read())
            return http_response
        except (socket.timeout, socket.error, ValueError) as ex:
            LOG.error(_('Vyatta vRouter REST API: Exception occurred while reading '
                        'the response: %s') % ex)
            raise VRouterConnectFailure(ip_address=self.address)            
        finally:
            conn.close()
                        