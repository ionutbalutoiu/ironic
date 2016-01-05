# -*- encoding: utf-8 -*-

from base64 import b64encode

from ironic.common.i18n import _

from ironic.common import states
from ironic.common import exception
from ironic.common import boot_devices
from ironic.drivers import base

from oslo_log import log as logging

from winrm import protocol

LOG = logging.getLogger(__name__)

REQUIRED_PROPERTIES = {
    'power_address': _("Power address"),
    'power_id': _("Power ID"),
    'power_user': _("Power user"),
    'power_pass': _("Power password"),
}

# WinRM constants
AUTH_BASIC = "basic"
AUTH_KERBEROS = "kerberos"
AUTH_CERTIFICATE = "certificate"
DEFAULT_PORT_HTTP = 5985
DEFAULT_PORT_HTTPS = 5986


def _get_vm_generation(driver_info):
    cmd_args = ["(Get-VM -VMName '%s').Generation" % driver_info['node_name']]
    std_out = _run_remote_ps_cmd(driver_info, cmd_args)
    return int(std_out.strip())


def _get_boot_devices_map(vm_generation):
    if vm_generation == 1:
        return {
            boot_devices.DISK: 'IDE',
            boot_devices.PXE: 'LegacyNetworkAdapter',
            boot_devices.CDROM: 'CD',
        }
    elif vm_generation == 2:
        return {
            boot_devices.DISK: 'HardDiskDrive',
            boot_devices.PXE: 'VMNetworkAdapter',
            boot_devices.CDROM: 'DvdDrive',
        }
    raise Exception("Unknown VM Generation.")


def _get_wsman_url(url=None, host=None, use_ssl=None, port=None):
    if url:
        return url
    else:
        if not port:
            if use_ssl:
                port = DEFAULT_PORT_HTTPS
            else:
                port = DEFAULT_PORT_HTTP

        if use_ssl:
            protocol = "https"
        else:
            protocol = "http"

        return ("%(protocol)s://%(host)s:%(port)s/wsman" % locals())


def _run_wsman_cmd(url=None, auth=None, username=None, password=None,
                  cert_pem=None, cert_key_pem=None, cmd=None):
    protocol.Protocol.DEFAULT_TIMEOUT = "PT3600S"

    if not auth:
        auth = AUTH_BASIC

    auth_transport_map = {AUTH_BASIC: 'plaintext',
                          AUTH_KERBEROS: 'kerberos',
                          AUTH_CERTIFICATE: 'ssl'}

    p = protocol.Protocol(endpoint=url,
                          transport=auth_transport_map[auth],
                          username=username,
                          password=password,
                          cert_pem=cert_pem,
                          cert_key_pem=cert_key_pem)

    shell_id = p.open_shell()

    command_id = p.run_command(shell_id, cmd[0], cmd[1:])
    std_out, std_err, status_code = p.get_command_output(shell_id, command_id)

    p.cleanup_command(shell_id, command_id)
    p.close_shell(shell_id)

    return (std_out, std_err, status_code)


def _run_remote_ps_cmd(driver_info, cmd_args, b64encoded=False):
    if b64encoded:
        ps_exec = ["powershell.exe", "-EncodedCommand"]
    else:
        ps_exec = ["powershell.exe", "-Command"]

    std_out, std_err, exit_code = _run_wsman_cmd(
            url=_get_wsman_url(host=driver_info['address'], use_ssl=True),
            auth="basic",
            username=driver_info['username'],
            password=driver_info['password'],
            cmd=(ps_exec + cmd_args))

    LOG.debug("EXIT CODE: %s" % exit_code)
    LOG.debug("STD_OUT: %s" % std_out)
    LOG.debug("STD_ERR: %s" % std_err)

    if exit_code != 0:
        raise Exception("Failed to execute remote PowerShell command. ")

    return std_out


def _set_power_state(driver_info, power_state):
    if power_state == states.POWER_ON:
        cmd_args = ["Start-VM", '%s' % driver_info['node_name']]
    elif power_state == states.POWER_OFF:
        cmd_args = ["Stop-VM", '%s' % driver_info['node_name'], "-TurnOff"]
    else:
        raise exception.InvalidParameterValue(
            _("set_power_state called "
              "with invalid power state %s.") % power_state)
    _run_remote_ps_cmd(driver_info, cmd_args)


def _parse_driver_info(node):
    """Gets the parameters required for to access the Hyper-V node.

    :param node: the Node of interest.
    :returns: dictionary of parameters.
    :raises: InvalidParameterValue when an invalid value is specified
    :raises: MissingParameterValue when a required ipmi parameter is missing.

    """
    info = node.driver_info or {}
    missing_info = [key for key in REQUIRED_PROPERTIES if not info.get(key)]
    if missing_info:
        raise exception.MissingParameterValue(_(
            "Missing the following parameters in the Hyper-V node's"
            " driver_info: %s.") % missing_info)

    address = info.get('power_address')
    node_name = info.get('power_id')
    username = info.get('power_user')
    password = info.get('power_pass')

    return {
        'address': address,
        'node_name': node_name,
        'username': username,
        'password': password,
    }


class HyperVPower(base.PowerInterface):

    def get_properties(self):
        """Return the properties of the interface.

        :returns: dictionary of <property name>:<property description> entries.
        """
        return REQUIRED_PROPERTIES

    def validate(self, task):
        """Validate the driver-specific Node power info.

        This method validates whether the 'driver_info' property of the
        supplied node contains the required information for this driver to
        manage the power state of the node. If invalid, raises an exception;
        otherwise, returns None.

        :param task: a TaskManager instance containing the node to act on.
        :raises: InvalidParameterValue
        :raises: MissingParameterValue
        """
        _parse_driver_info(task.node)

    def get_power_state(self, task):
        """Return the power state of the task's node.

        :param task: a TaskManager instance containing the node to act on.
        :raises: MissingParameterValue if a required parameter is missing.
        :returns: a power state. One of :mod:`ironic.common.states`.
        """
        driver_info = _parse_driver_info(task.node)
        cmd_args = ["(Get-VM '%s').State" % driver_info['node_name']]
        std_out = _run_remote_ps_cmd(driver_info, cmd_args)
        if std_out == "Off\r\n":
            return states.POWER_OFF
        elif std_out == "Running\r\n":
            return states.POWER_ON
        else:
            raise Exception("Unknown power state. STD_OUT from remote PS "
                            "call: %s" % std_out)

    def set_power_state(self, task, power_state):
        """Set the power state of the task's node.

        :param task: a TaskManager instance containing the node to act on.
        :param power_state: Any power state from :mod:`ironic.common.states`.
        :raises: MissingParameterValue if a required parameter is missing.
        """
        driver_info = _parse_driver_info(task.node)
        _set_power_state(driver_info, power_state)

    def reboot(self, task):
        """Perform a hard reboot of the task's node.

        Drivers are expected to properly handle case when node is powered off
        by powering it on.

        :param task: a TaskManager instance containing the node to act on.
        :raises: MissingParameterValue if a required parameter is missing.
        """
        driver_info = _parse_driver_info(task.node)
        _set_power_state(driver_info, states.POWER_OFF)
        _set_power_state(driver_info, states.POWER_ON)


class HyperVManagement(base.ManagementInterface):

    def get_properties(self):
        return REQUIRED_PROPERTIES

    def validate(self, task):
        _parse_driver_info(task.node)

    def get_supported_boot_devices(self, task):
        """Get a list of the supported boot devices.

        :param task: a task from TaskManager.
        :returns: A list with the supported boot devices defined
                  in :mod:`ironic.common.boot_devices`.

        """
        return [
            boot_devices.DISK,
            boot_devices.PXE,
            boot_devices.CDROM
        ]

    def set_boot_device(self, task, device, persistent=False):
        """Set the boot device for the task's node.

        Set the boot device to use on next reboot of the node.

        """
        driver_info = _parse_driver_info(task.node)
        vm_generation = _get_vm_generation(driver_info)
        boot_devices_map = _get_boot_devices_map(vm_generation)
        ps_script = """
        $ErrorActionPreference = "Stop";
        $vmName = '%s';
        $deviceName = '%s';

        $gen = (Get-VM $vmName).Generation;
        switch ($gen) {
            1 {
                $vmBios = Get-VMBios -VMName $vmName;
                $bootOrder = $vmBios.StartupOrder;
                if ($bootOrder[0] -eq $deviceName) {
                    Write-Host ("'$deviceName' is already set as first " +
                                "boot device.");
                    exit 0;
                }

                $device = $null;
                foreach ($bootDevice in $bootOrder) {
                    if ($bootDevice -eq $deviceName) {
                        $device = $bootDevice;
                        break;
                    }
                }

                $index = $bootOrder.IndexOf($device);
                if ($index -eq -1) {
                    Write-Host "'$deviceName' boot device can't be found.";
                    exit 1;
                }

                $oldBootDevice = $bootOrder[0];
                $bootOrder[0] = $device;
                $bootOrder[$index] = $oldBootDevice;

                if ((Get-VM -VMName $vmName).State -eq 'Running') {
                    Stop-VM -VMName $vmName -TurnOff;
                    Set-VMBios -VMName $vmName -StartupOrder $bootOrder;
                    Start-VM -VMName $vmName;
                } else {
                    Set-VMBios -VMName $vmName -StartupOrder $bootOrder;
                }
            }

            2 {
                $bootOrder = (Get-VMFirmware $vmName).BootOrder;
                $validBootTypes = @('Drive', 'Network');
                $validBootDevices = @();
                foreach ($bootDevice in $bootOrder) {
                    if (($bootDevice.BootType -in $validBootTypes) -and
                        ($bootDevice.Device.GetType().Name -eq $deviceName)) {
                        $validBootDevices += $bootDevice;
                    }
                }

                if ($validBootDevices.Length -eq 0) {
                    Write-Host "No '$deviceName' boot device found.";
                    exit 1;
                }

                $device = $validBootDevices[0];
                $index = $bootOrder.IndexOf($device);
                if ($index -eq 0) {
                    Write-Host ("'$deviceName' is already set as first " +
                                "boot device.");
                    exit 0;
                }

                $oldBootDevice = $bootOrder[0];
                $bootOrder[0] = $device;
                $bootOrder[$index] = $oldBootDevice;

                Set-VMFirmware -VMName $vmName -BootOrder $bootOrder;
            }

            default {
                Write-Host "Cannot set '$deviceName' as first boot device.";
                exit 1
            }
        }
        Write-Host "'$deviceName' successfully set as first boot device.";
        """ % (driver_info['node_name'], boot_devices_map[device])

        encoded_script = b64encode(ps_script.encode("utf-16-le"))
        _run_remote_ps_cmd(driver_info, [encoded_script], b64encoded=True)

    def get_boot_device(self, task):
        driver_info = _parse_driver_info(task.node)
        vm_generation = _get_vm_generation(driver_info)
        boot_devices_map = _get_boot_devices_map(vm_generation)
        ps_script = """
        $ErrorActionPreference = "Stop";
        $vmName = '%s';
        $gen = (Get-VM $vmName).Generation;
        switch ($gen) {
            1 {
                Write-Host (Get-VMBios -VMName $vmName).StartupOrder[0];
                exit 0
            }
            2 {
                $firstBootSource = (Get-VMFirmware $vmName).BootOrder[0];
                if ($firstBootSource.BootType -in @('Drive', 'Network')) {
                    Write-Host $firstBootSource.Device.GetType().Name;
                    exit 0
                }
            }
            default {
                exit 1
            }
        }
        """ % (driver_info['node_name'])

        encoded_script = b64encode(ps_script.encode("utf-16-le"))
        std_out = _run_remote_ps_cmd(driver_info, [encoded_script],
                                     b64encoded=True)

        # Standard output from WinRM call comes with whitespaces at the end, we
        # just strip those.
        current_boot_device = std_out.strip()
        for boot_device, boot_device_hyperv in boot_devices_map.iteritems():
            if current_boot_device == boot_device_hyperv:
                return {'boot_device': boot_device, 'persistent': True}

        return {'boot_device': None, 'persistent': None}

    def get_sensors_data(self, task):
        """Get sensors data.

        Not implemented by this driver.

        :param task: a TaskManager instance.

        """
        raise NotImplementedError()
