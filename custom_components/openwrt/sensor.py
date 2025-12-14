from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.components.sensor import SensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.components.sensor import SensorDeviceClass

import logging

from . import OpenWrtEntity
from .constants import DOMAIN
from datetime import timedelta

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities
) -> None:

    entities = []
    data = entry.as_dict()
    device = hass.data[DOMAIN]['devices'][entry.entry_id]
    device_id = data['data']['id']

    # Add hosts sensor
    entities.append(HostsSensor(device, device_id))


    wireless = []
    for net_id in device.coordinator.data['wireless']:
        sensor = WirelessClientsSensor(device, device_id, net_id)
        wireless.append(sensor)
        entities.append(sensor)
    if len(wireless) > 0:
        entities.append(WirelessTotalClientsSensor(
            device, device_id, wireless))
    for net_id in device.coordinator.data['mesh']:
        entities.append(
            MeshSignalSensor(device, device_id, net_id)
        )
        entities.append(
            MeshPeersSensor(device, device_id, net_id)
        )
#    for net_id in device.coordinator.data["mwan3"]:
#        entities.append(
#            Mwan3OnlineSensor(device, device_id, net_id)
#        )
    # Validate mwan3 data before creating sensors; ignore invalid entries
    mwan3_data = device.coordinator.data.get("mwan3", {})
    if isinstance(mwan3_data, dict):
        for net_id, net_data in mwan3_data.items():
            if not isinstance(net_data, dict):
                _LOGGER.warning(
                    "Skipping mwan3 entry '%s' for device %s: data is not a dict",
                    net_id,
                    device_id,
                )
                continue
            # Ensure required numeric fields exist and are numbers
            try:
                uptime = net_data.get("uptime_sec")
                online = net_data.get("online_sec")
                # Accept integers or strings that can be converted to int
                if uptime is None or online is None:
                    raise ValueError("missing uptime_sec or online_sec")
                uptime_val = int(uptime)
                online_val = int(online)
            except Exception as err:
                _LOGGER.warning(
                    "Skipping mwan3 entry '%s' for device %s: invalid data (%s)",
                    net_id,
                    device_id,
                    err,
                )
                continue

            entities.append(
                Mwan3OnlineSensor(device, device_id, net_id)
            )
    else:
        _LOGGER.debug("No valid 'mwan3' data available for device %s", device_id)

    for net_id in device.coordinator.data["wan"]:
        entities.append(
            WanRxTxSensor(device, device_id, net_id, "rx")
        )
        entities.append(
            WanRxTxSensor(device, device_id, net_id, "tx")
        )
    # Add system info sensors
    if "system_info" in device.coordinator.data:
        entities.append(SystemUptimeSensor(device, device_id))
        entities.append(SystemLoadSensor(device, device_id))
        entities.append(SystemMemorySensor(device, device_id))
        #entities.append(SystemDiskSensor(device, device_id, "root"))
        #entities.append(SystemDiskSensor(device, device_id, "tmp"))
        if device.coordinator.data["system_info"].get("swap", {}).get("total", 0) > 0:
            entities.append(SystemDiskSensor(device, device_id, "swap"))
    async_add_entities(entities)
    return True


class OpenWrtSensor(OpenWrtEntity, SensorEntity):
    """Base class for OpenWrt sensors."""
    def __init__(self, coordinator, device: str):
        super().__init__(coordinator, device)

    @property
    def state_class(self):
        return 'measurement'


class WirelessClientsSensor(OpenWrtSensor):
    """Sensor to show the number of clients in a wireless interface."""

    def __init__(self, device, device_id: str, interface: str):
        super().__init__(device, device_id)
        self._interface_id = interface

    @property
    def unique_id(self):
        return "%s.%s.clients" % (super().unique_id, self._interface_id)

    @property
    def name(self):
        #return "%s Wireless [%s] clients" % (super().name, self._interface_id)
        # Get the SSID from the data, or use the interface ID if not available
        ssid = self.data['wireless'][self._interface_id].get('ssid', self._interface_id)
        return "%s Wireless [%s] clients" % (super().name, ssid)

    @property
    def state(self):
        return self.data['wireless'][self._interface_id]['clients']

    @property
    def icon(self):
        return 'mdi:wifi-off' if self.state == 0 else 'mdi:wifi'

    @property
    def extra_state_attributes(self):
        result = dict()
        data = self.data['wireless'][self._interface_id]
        _LOGGER.debug(f"Generando atributos para {self._interface_id} con datos: {data}")
        
        # Get host information from hosts data
        hosts_data = self.data.get('hosts', {})
        _LOGGER.debug(f"Datos de hosts disponibles: {len(hosts_data)} entradas")
        
        mac_to_ip = {}
        mac_to_name = {}
        
        # Create mappings from MAC to IP and name
        for mac, host_info in hosts_data.items():
            mac_lower = mac.lower()  # Store lowercase MAC for consistent matching
            mac_to_ip[mac_lower] = host_info.get("ip", "")
            mac_to_name[mac_lower] = host_info.get("name", "")
        
        # Add client information with IP and name if available
        for mac, value in data.get("macs", {}).items():
            mac_lower = mac.lower()
            signal = value.get("signal", 0)
            client_info = f"{signal} dBm"
            
            # Add IP and name information if available
            if mac_lower in mac_to_ip and mac_to_ip[mac_lower]:
                client_info += f" | IP: {mac_to_ip[mac_lower]}"
                
            if mac_lower in mac_to_name and mac_to_name[mac_lower]:
                client_info += f" | Nombre: {mac_to_name[mac_lower]}"
                
            result[mac.upper()] = client_info

        # Include the SSID in the sensor attributes
        if 'ssid' in data:
            result['ssid'] = data['ssid']            
        return result

    @property
    def entity_category(self):
        return EntityCategory.DIAGNOSTIC


class MeshSignalSensor(OpenWrtSensor):
    """Sensor to show the signal strength of a mesh interface."""

    def __init__(self, device, device_id: str, interface: str):
        super().__init__(device, device_id)
        self._interface_id = interface

    @property
    def unique_id(self):
        return "%s.%s.mesh_signal" % (super().unique_id, self._interface_id)

    @property
    def name(self):
        return f"{super().name} Mesh [{self._interface_id}] signal"

    @property
    def state(self):
        value = self.data['mesh'][self._interface_id]['signal']
        return f"{value} dBm"

    @property
    def device_class(self):
        return 'signal_strength'

    @property
    def signal_strength(self):
        value = self.data['mesh'][self._interface_id]['signal']
        levels = [-50, -60, -67, -70, -80]
        for idx, level in enumerate(levels):
            if value >= level:
                return idx
        return len(levels)

    @property
    def icon(self):
        icons = ['mdi:network-strength-4', 'mdi:network-strength-3', 'mdi:network-strength-2',
                 'mdi:network-strength-1', 'mdi:network-strength-outline', 'mdi:network-strength-off-outline']
        return icons[self.signal_strength]

    @property
    def entity_category(self):
        return EntityCategory.DIAGNOSTIC


class MeshPeersSensor(OpenWrtSensor):
    """Sensor to show the number of active mesh peers in a mesh interface."""

    def __init__(self, device, device_id: str, interface: str):
        super().__init__(device, device_id)
        self._interface_id = interface

    @property
    def unique_id(self):
        return "%s.%s.mesh_peers" % (super().unique_id, self._interface_id)

    @property
    def name(self):
        return f"{super().name} Mesh [{self._interface_id}] peers"

    @property
    def state(self):
        peers = self.data["mesh"][self._interface_id]["peers"]
        return len(list(filter(lambda x: x["active"], peers.values())))

    @property
    def icon(self):
        return 'mdi:server-network' if self.state > 0 else 'mdi:server-network-off'

    @property
    def extra_state_attributes(self):
        result = dict()
        data = self.data["mesh"][self._interface_id]
        for key, value in data.get("peers", {}).items():
            signal = value.get("signal", 0)
            result[key.upper()] = f"{signal} dBm"
        return result

    @property
    def entity_category(self):
        return EntityCategory.DIAGNOSTIC


class WirelessTotalClientsSensor(OpenWrtSensor):
    """Sensor to show the total number of clients in all wireless interfaces."""

    def __init__(self, device, device_id: str, sensors):
        super().__init__(device, device_id)
        self._sensors = sensors

    @property
    def unique_id(self):
        return "%s.total_clients" % (super().unique_id)

    @property
    def name(self):
        return "%s Wireless total clients" % (super().name)

    @property
    def state(self):
        total = 0
        for item in self._sensors:
            total += item.state
        return total

    @property
    def icon(self):
        return 'mdi:wifi-off' if self.state == 0 else 'mdi:wifi'

    @property
    def extra_state_attributes(self):
        # Add SSID information as attributes
        result = {}
        for sensor in self._sensors:
            ssid = sensor.data['wireless'][sensor._interface_id].get('ssid', sensor._interface_id)
            result[ssid] = sensor.state
        return result

class Mwan3OnlineSensor(OpenWrtSensor):
    """Sensor to show the online ratio of a WAN interface."""

    def __init__(self, device, device_id: str, interface: str):
        super().__init__(device, device_id)
        self._interface_id = interface
        self._attr_native_unit_of_measurement = "%"
        self._attr_icon = "mdi:router-network"
        self._attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def available(self):
        return self._interface_id in self.data["mwan3"]

    @property
    def unique_id(self):
        return "%s.%s.mwan3_online_ratio" % (super().unique_id, self._interface_id)

    @property
    def name(self):
        return f"{super().name} Mwan3 [{self._interface_id}] online ratio"

    @property
    def native_value(self):
        data = self.data["mwan3"].get(self._interface_id, {})
        value = data.get("online_sec") / data.get("uptime_sec") * \
            100 if data.get("uptime_sec") else 100
        return round(value, 1)


class WanRxTxSensor(OpenWrtSensor):
    """Sensor to show the RX/TX bytes of a WAN interface."""

    def __init__(self, device, device_id: str, interface: str, code: str):
        super().__init__(device, device_id)
        self._interface = interface
        self._code = code
        self._attr_entity_category = EntityCategory.DIAGNOSTIC
        self._attr_icon = "mdi:download-network" if code == "rx" else "mdi:upload-network"
        self._attr_device_class = SensorDeviceClass.DATA_SIZE
        self._attr_native_unit_of_measurement = "B"

    @property 
    def _data(self):
        return self.data["wan"].get(self._interface) 

    @property
    def available(self):
        return self._interface in self.data["wan"] and self._data.get("up")

    @property
    def unique_id(self):
        return "%s.%s.wan_%s_bytes" % (super().unique_id, self._interface, self._code)

    @property
    def name(self):
        return f"{super().name} Wan [{self._interface}] {self._code.capitalize()} bytes"

    @property
    def native_value(self):
        return self._data.get(f"{self._code}_bytes")

    @property
    def extra_state_attributes(self):
        return dict(mac=self._data.get("mac"), speed=self._data.get("speed"))

    @property
    def state_class(self):
        return "total_increasing"

class HostsSensor(OpenWrtSensor):
    """Sensor to show the number of known hosts in the router."""
    def __init__(self, device, device_id: str):
        super().__init__(device, device_id)
        #self._attr_entity_category = EntityCategory.DIAGNOSTIC
        self._attr_icon = "mdi:devices"

    @property
    def unique_id(self):
        return "%s.hosts" % (super().unique_id)

    @property
    def name(self):
        return f"{super().name} Known Hosts"

    @property
    def state(self):
        if "hosts" not in self.data:
            return 0
        return len(self.data["hosts"])

    @property
    def extra_state_attributes(self):
        if "hosts" not in self.data:
            return {}
        
        # Organize hosts by IP address
        ip_to_host = {}
        for mac, host_data in self.data["hosts"].items():
            ip = host_data.get("ip", "")
            name = host_data.get("name", "")
            if ip:  # Only include hosts with IP addresses
                ip_to_host[ip] = {
                    "name": name,
                    "mac": mac
                }
        
        # Sort by IP address (numerically)
        sorted_ips = sorted(ip_to_host.keys(), key=self._sort_ip)
        
        # Create result with the format "IP : Nombre : MAC"
        result = {}
        for ip in sorted_ips:
            host_info = ip_to_host[ip]
            name = host_info["name"] if host_info["name"] else "Desconocido"
            mac = host_info["mac"]
            result[ip] = f"{name} : {mac}"
        
        return result
    
    def _sort_ip(self, ip):
        """Helper function to sort IPs numerically"""
        try:
            # Convert each octet to int for proper numerical sorting
            return [int(n) for n in ip.split('.')]
        except (ValueError, AttributeError):
            # In case of invalid IP format, return a default value
            return [999, 999, 999, 999]

class SystemUptimeSensor(OpenWrtSensor):
    """System uptime sensor."""

    def __init__(self, device, device_id: str):
        super().__init__(device, device_id)
        self._attr_entity_category = EntityCategory.DIAGNOSTIC
        self._attr_icon = "mdi:clock-outline"

    @property
    def unique_id(self):
        return "%s.system_uptime" % (super().unique_id)

    @property
    def name(self):
        return f"{super().name} System uptime"

    @property
    def state(self):
        seconds = self.data.get("system_info", {}).get("uptime", 0)
        # Format uptime as days, hours, minutes
        delta = timedelta(seconds=seconds)
        days = delta.days
        hours = delta.seconds // 3600
        minutes = (delta.seconds % 3600) // 60
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"

    @property
    def extra_state_attributes(self):
        return {
            "seconds": self.data.get("system_info", {}).get("uptime", 0)
        }

class SystemMemorySensor(OpenWrtSensor):
    """System memory sensor."""

    def __init__(self, device, device_id: str):
        super().__init__(device, device_id)
        self._attr_entity_category = EntityCategory.DIAGNOSTIC
        self._attr_icon = "mdi:memory"
        self._attr_native_unit_of_measurement = "MB"

    @property
    def unique_id(self):
        return "%s.system_memory_free" % (super().unique_id)

    @property
    def name(self):
        return f"{super().name} System memory free"

    @property
    def native_value(self):
        memory = self.data.get("system_info", {}).get("memory", {})
        free = memory.get("free", 0)
        # Convert bytes to MB
        return round(free / (1024 * 1024), 1)

    @property
    def extra_state_attributes(self):
        memory = self.data.get("system_info", {}).get("memory", {})
        # Convert all values to MB for better readability
        return {
            "total_mb": round(memory.get("total", 0) / (1024 * 1024), 1),
            "free_mb": round(memory.get("free", 0) / (1024 * 1024), 1),
            "shared_mb": round(memory.get("shared", 0) / (1024 * 1024), 1),
            "cached_mb": round(memory.get("cached", 0) / (1024 * 1024), 1),
            "available_mb": round(memory.get("available", 0) / (1024 * 1024), 1),
            "used_percent": round((1 - memory.get("free", 0) / memory.get("total", 1)) * 100, 1)
        }

class SystemLoadSensor(OpenWrtSensor):
    """System load sensor."""

    def __init__(self, device, device_id: str):
        super().__init__(device, device_id)
        self._attr_entity_category = EntityCategory.DIAGNOSTIC
        self._attr_icon = "mdi:cpu-64-bit"

    @property
    def unique_id(self):
        return "%s.system_load" % (super().unique_id)

    @property
    def name(self):
        return f"{super().name} System load"

    @property
    def state(self):
        # Get the 1 minute load average and divide by 65536 (as per OpenWrt ubus format)
        load = self.data.get("system_info", {}).get("load", [0, 0, 0])
        if load and len(load) >= 3:
            return round(load[0] / 65536, 2)
        return 0

    @property
    def extra_state_attributes(self):
        load = self.data.get("system_info", {}).get("load", [0, 0, 0])
        if load and len(load) >= 3:
            return {
                "load_1min": round(load[0] / 65536, 2),
                "load_5min": round(load[1] / 65536, 2),
                "load_15min": round(load[2] / 65536, 2),
            }
        return {}




#class SystemDiskSensor(OpenWrtSensor):
#    """System disk sensor."""
#
#    def __init__(self, device, device_id: str, disk_type: str):
#        super().__init__(device, device_id)
#        self._disk_type = disk_type
#        self._attr_entity_category = EntityCategory.DIAGNOSTIC
#        self._attr_icon = "mdi:harddisk"
#        self._attr_native_unit_of_measurement = "%"
#
#    @property
#    def unique_id(self):
#        return f"{super().unique_id}.{self._disk_type}_usage"
#
#    @property
#    def name(self):
#        return f"{super().name} {self._disk_type.capitalize()} usage"
#
#    @property
#    def native_value(self):
#        disk_info = self.data.get("system_info", {}).get(self._disk_type, {})
#        total = disk_info.get("total", 0)
#        free = disk_info.get("free", 0)
#        if total > 0:
#            return round((1 - free / total) * 100, 1)
#        return 0
#
#    @property
#    def extra_state_attributes(self):
#        disk_info = self.data.get("system_info", {}).get(self._disk_type, {})
#        return {
#            "total_kb": disk_info.get("total", 0),
#            "free_kb": disk_info.get("free", 0),
#            "used_kb": disk_info.get("used", 0),
#            "avail_kb": disk_info.get("avail", 0)
#        }

