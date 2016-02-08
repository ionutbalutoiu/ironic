# Copyright 2015 Cloudbase Solutions Srl
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

import json
import os
import subprocess

from ironic.common import exception
from ironic.dhcp import base

from jinja2 import Template
from netaddr import IPAddress
from netaddr import IPNetwork
from netaddr import IPRange
from netaddr import IPSet
from oslo_config import cfg


DHCPD_CONF_TEMPLATE = """
ddns-update-style none;
log-facility local7;
authoritative;
default-lease-time {{ default_lease_time }};
max-lease-time {{ max_lease_time }};

subnet {{ subnet }} netmask {{ netmask }} {
    option routers {{ gateway }};
    option domain-name-servers {{ domain_name_servers }};
}

{% for host_file in host_files -%}
include "{{ host_file }}";
{% endfor %}
"""

HOST_TEMPLATE = """# {{ ctxt_json }}
host {{ node_uuid }} {
    hardware ethernet {{ mac_address }};
    fixed-address {{ ip_address }};

{% if ipxe_boot_file %}
    if exists user-class and option user-class = "iPXE" {
        option bootfile-name "{{ ipxe_boot_file }}";
    } else {
        option bootfile-name "{{ pxe_boot_file }}";
    }
    option tftp-server-name "{{ tftp_server }}";
{% else %}
    option bootfile-name "{{ pxe_boot_file }}";
    option tftp-server-name "{{ tftp_server }}";
{% endif -%}
}
"""

dhcpd_opts = [
    cfg.StrOpt('subnet',
               help='Subnet to be used by the dhcpd server. This should be '
                    'given in the CIDR format.'),
    cfg.StrOpt('reserved_ip_range',
               help='IP range reserved for the Ironic nodes. The value must '
                    'be of the form "<start_ip>-<end_ip>" (dash delimited) '
                    'and from the given subnet.'),
    cfg.StrOpt('gateway',
               help='Gateway used by the clients.'),
    cfg.StrOpt('domain_name_servers',
               help='Comma separated list of domain name servers IPs.'),
    cfg.IntOpt('default_lease_time',
               default=600,
               help='Length in seconds that will be assigned to a lease if '
                    'the client requesting the lease does not ask for a '
                    'specific expiration time.'),
    cfg.IntOpt('max_lease_time',
               default=7200,
               help='Maximum length in seconds that will be assigned to '
                    'a lease.'),
    cfg.StrOpt('dhcpd_service_name',
               default='ironic-dhcpd',
               help='Dhcpd service name used by Ironic.'),
    cfg.StrOpt('dhcpd_conf',
               default='/etc/dhcp/ironic/ironic-dhcpd.conf',
               help='Configuration file for the dhcpd service used by '
                    'Ironic.'),
    cfg.StrOpt('reservations_dir',
               default='/etc/dhcp/ironic/reservations',
               help='Directory used to store node reservations files.')
]

CONF = cfg.CONF
CONF.register_opts(dhcpd_opts, group='dhcpd')


def _get_dir_files(directory):
    """Returns a list with all the files paths from a given directory. Paths
       are relative to the given parameter directory path.
    """
    if not (os.path.exists(directory) and os.path.isdir(directory)):
        return []
    files = []
    for _file in os.listdir(directory):
        files.append(os.path.join(directory, _file))
    return files


class ReservationsParser(object):
    """Responsible for parsing all the host files that are present in the
       `reservations_dir` and are included in the DHCPD configuration file.
    """

    def __init__(self, reservations_dir):
        self.reservations_dir = reservations_dir

    def parse_host_file(self, host_file):
        """Returns a dictionary with the Ironic node DHCP reservation after
           the host file is parsed. By convention and to ease the parsing,
           the header of a host file included in the DHCPD configuration
           file contains the JSON encoded context used to render the template.
        """
        if not os.path.exists(host_file):
            raise Exception("Given host file path does not exist.")
        if os.path.isdir(host_file):
            raise Exception("Given host file path is a directory. Cannot "
                            "parse it.")
        with open(host_file, 'r') as f:
            # read first line containing the JSON encoded dictionary of the
            # DHCP reservation for the node.
            json_ctxt = f.readline()
        # remove starting '# ' characters and ending newline character '\n'
        json_ctxt = json_ctxt[2:-1]
        return json.loads(json_ctxt)

    def get_reservations(self):
        """Returns a dictionary with the DHCP boot options for all provisioned
           Ironic nodes. The dictionary keys are the nodes UUIDs and the
           values are the DHCP boot options. The function iterates over each
           host file from the reservations directory and parses it by reading
           its header which is an encoded JSON of the DHCP reservation.
        """
        reservations = {}
        host_files = _get_dir_files(self.reservations_dir)
        for host_file in host_files:
            reservations_parsed = self.parse_host_file(host_file)
            node_uuid = reservations_parsed.pop('node_uuid')
            reservations[node_uuid] = reservations_parsed
        return reservations


class DhcpdProvider(base.BaseDHCP):
    """DHCPD provider to be used by Ironic."""

    def __init__(self):
        self.reservations_parser = ReservationsParser(
                                        CONF.dhcpd.reservations_dir)

    def _dhcp_reservations(self):
        """Returns a dictionary with DHCP reservations for all provisioned
           Ironic nodes.
        """
        return self.reservations_parser.get_reservations()

    def _dhcpd_service(self, action):
        """Controls the Ironic DHCPD service.
        """
        valid_actions = ['start', 'stop', 'status', 'restart', 'reload']
        if action not in valid_actions:
            raise Exception('Invalid service action! Action %s was given, '
                            'but valid action are: %s' % valid_actions)
        cmd = ['service',
               CONF.dhcpd.dhcpd_service_name,
               action]
        subprocess.check_output(cmd)

    def _dhcpd_service_reload(self):
        """Try to reload the Ironic DHCPD service and if that fails, a restart
           is attempted as well.
        """
        try:
            self._dhcpd_service('reload')
        except subprocess.CalledProcessError:
            # Failed to reload the service. Trying to restart it...
            self._dhcpd_service('restart')

    def _render_dhcpd_conf(self):
        """Generates the config file used by the DHCPD server.
        """
        host_files = _get_dir_files(CONF.dhcpd.reservations_dir)
        ip_network = IPNetwork(CONF.dhcpd.subnet)
        dhcpd_conf_ctxt = {
            'default_lease_time': CONF.dhcpd.default_lease_time,
            'max_lease_time': CONF.dhcpd.max_lease_time,
            'subnet': ip_network.network,
            'netmask': ip_network.netmask,
            'gateway': CONF.dhcpd.gateway,
            'domain_name_servers': CONF.dhcpd.domain_name_servers,
            'host_files': host_files
        }
        conf_template = Template(DHCPD_CONF_TEMPLATE)
        conf_template.stream(dhcpd_conf_ctxt).dump(CONF.dhcpd.dhcpd_conf)
        self._dhcpd_service_reload()

    def _reserved_ip_addresses(self):
        """Returns a list with the reserved IP addresses for all the
           provisioned Ironic nodes.
        """
        ips = []
        reservations = self._dhcp_reservations()
        for node_uuid, node_properties in reservations.iteritems():
            ips.append(node_properties['ip_address'])
        return ips

    def _reserve_ip_address(self):
        """This function reserves an unused IP address from the range. If
           there are no more free IPs, an exception will be raised.
        """
        ip_range = CONF.dhcpd.reserved_ip_range.split('-')
        reserved_ips = IPSet(IPRange(ip_range[0], ip_range[1]))
        allocated_ips = IPSet(self._reserved_ip_addresses())
        # difference between sets
        free_ips = reserved_ips ^ allocated_ips

        if len(free_ips) == 0:
            # After exception is raised, the node is put into 'deploy failed'
            # provision state.
            # NOTE: ironic-conductor process isn't interrupted.
            raise Exception('No more available IPs.')
        return IPAddress(free_ips.pop())

    def _parse_ironic_dhcp_options(self, dhcp_options):
        """Parses the dnsmasq DHCP boot options sent by Ironic and returns a
           simpler dict with the options.

           Example:

           For `dhcp_options` parameter:
           [{'opt_name': '!175,bootfile-name', 'opt_value': 'undionly.kpxe'},
            {'opt_name': 'bootfile-name',
             'opt_value': 'http://10.0.190.100:8080/boot.ipxe'},
            {'opt_name': 'server-ip-address', 'opt_value': '10.0.190.100'},
            {'opt_name': 'tftp-server', 'opt_value': '10.0.190.100'}]

           The returned dict is:
           {'!175,bootfile-name': 'undionly.kpxe',
            'bootfile-name':      'http://10.0.190.100:8080/boot.ipxe',
            'server-ip-address':  '10.0.190.100',
            'tftp-server':        '10.0.190.100'}
        """
        return {opt['opt_name']: opt["opt_value"] for opt in dhcp_options}

    def _render_dhcpd_host_file(self, node_uuid, port_uuid, mac_address,
                                ip_address, dhcp_opts, context=None):
        """Creates the host file with the DHCP reservations which will be
           included in the configuration file.
           `dhcp_opts` received as parameter is a dictionary returned by
           the function `_parse_ironic_dhcp_options`.
        """
        if context and type(context) is dict:
            # Don't bother trying to create the context if it was already given
            # as parameter. This is used when we want to update the parameters
            # from a host file (like for example in the function
            # `update_port_address`).
            # TODO(Ionut): Do more validation on the context parameter. We
            #              need to verify that it has all the required values
            #              to render the template.
            context['ctxt_json'] = json.dumps(context, ensure_ascii=False)
            host_template = Template(HOST_TEMPLATE)
            host_file = os.path.join(CONF.dhcpd.reservations_dir,
                                     context['node_uuid'])
            host_template.stream(context).dump(host_file)
            return

        if '!175,bootfile-name' in dhcp_opts:
            # iPXE is enabled
            pxe_boot_file = dhcp_opts['!175,bootfile-name']
            ipxe_boot_file = dhcp_opts['bootfile-name']
        else:
            # iPXE is disabled
            pxe_boot_file = dhcp_opts['bootfile-name']
            ipxe_boot_file = ''

        ctxt = {
            'node_uuid': node_uuid,
            'port_uuid': port_uuid,
            'mac_address': mac_address,
            'ip_address': ip_address,
            'pxe_boot_file': pxe_boot_file,
            'ipxe_boot_file': ipxe_boot_file,
            'tftp_server': dhcp_opts['tftp-server']
        }
        # Encode the DHCP boot options as JSON and put them as comment at
        # the beginning of the file. This makes parsing the file easier as we
        # just need to read the header with the JSON.
        ctxt['ctxt_json'] = json.dumps(ctxt, ensure_ascii=False)

        host_template = Template(HOST_TEMPLATE)
        host_file = os.path.join(CONF.dhcpd.reservations_dir, node_uuid)
        host_template.stream(ctxt).dump(host_file)

    def update_port_dhcp_opts(self, port_id, dhcp_options, token=None):
        """Update one or more DHCP options on the specified port.
        """
        dhcp_reservations = self._dhcp_reservations()
        node_uuid = None
        for _node_uuid, node_properties in dhcp_reservations.iteritems():
            if node_properties['port_uuid'] == port_id:
                node_uuid = _node_uuid
                break
        if not node_uuid:
            raise exception.FailedToUpdateDHCPOptOnPort(port_id=port_id)

        self._render_dhcpd_host_file(
            node_uuid=node_uuid,
            port_uuid=port_id,
            mac_address=dhcp_reservations[node_uuid]['mac_address'],
            ip_address=dhcp_reservations[node_uuid]['ip_address'],
            dhcp_opts=self._parse_ironic_dhcp_options(dhcp_options))
        self._render_dhcpd_conf()

    def update_dhcp_opts(self, task, options, vifs=None):
        """Send or update the DHCP BOOT options for this node.
        """
        # get the MAC address for the first port of the BareMetal node and
        # reserve an IP for it
        dhcp_port = task.ports[0]
        self._render_dhcpd_host_file(
            node_uuid=task.node.uuid,
            port_uuid=dhcp_port.uuid,
            mac_address=dhcp_port.address,
            # We need to cast the returned IPAddress to 'str' because the
            # IPAddress instance from netaddr is not JSON serializable.
            ip_address=str(self._reserve_ip_address()),
            dhcp_opts=self._parse_ironic_dhcp_options(options))
        self._render_dhcpd_conf()

    def update_port_address(self, port_id, address, token=None):
        """Update a port's MAC address.
        """
        dhcp_reservations = self._dhcp_reservations()
        for node_uuid, node_properties in dhcp_reservations.iteritems():
            if dhcp_reservations[node_uuid]['port_uuid'] == port_id:
                # Get the old context by parsing the host reservation file
                # Update it with the new MAC address for the port
                # Render the host_file and dhpd
                ctxt = self.reservations_parser.parse_host_file(
                    os.path.join(CONF.dhcpd.reservations_dir, node_uuid))
                ctxt['mac_address'] = address
                self._render_dhcpd_host_file(contxt=ctxt)
                self._dhcpd_service_reload()
                break

    def get_ip_addresses(self, task):
        """Get IP addresses for all ports in `task` (TaskManager instance).
        """
        dhcp_reservations = self._dhcp_reservations()
        ip_addresses = []
        for port in task.ports:
            for node_uuid, node_properties in dhcp_reservations:
                if node_properties['port_uuid'] == port.uuid:
                    ip_addresses.append(node_properties['ip_address'])
        return ip_addresses

    def clean_dhcp_opts(self, task):
        """Removes the DHCP reservations by deleting the host file from the
           reservations directory.
        """
        host_file = os.path.join(CONF.dhcpd.reservations_dir, task.node.uuid)
        os.remove(host_file)
