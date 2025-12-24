# Home Assistant integration with OpenWrt devices

**Forked from [kvj/hass_openwrt](https://github.com/kvj/hass_openwrt)**

[![hacs_badge](https://img.shields.io/badge/HACS-custom-orange.svg?style=for-the-badge)](https://github.com/custom-components/hacs)


## Features

* Sensors:
  * Wireless clients counters (per interface/SSID) with client details (signal, IP, name)
  * Wireless total clients (aggregate across interfaces)
  * Known hosts sensor (lists IP, name and MAC)
   * Number of connected mesh peers
   * Signal strength of mesh links
  * `mwan3` interface online ratio (validated to avoid invalid data)
  * WAN interfaces Rx & Tx bytes counters (if configured)
  * System sensors: uptime, load and memory (swap/disk usage when available)
* Switches:
  * Control WPS status
* Binary sensors:
  * `mwan3` connectivity status
* Services:
  * Reboot device: `openwrt.reboot`
  * Execute arbitrary command: `openwrt.exec` (see the configuration below)
  * Manage services using command-line: `openwrt.init` (see the configuration below)

### Installing
### Automatic setup
You can use the 'auto-setup.sh' script to automate the following router configuration steps.
The script must be copied to and executed directly on the router (e.g. via SSH); it must not be run from your local machine or from within the repository.
The script will check for required packages, create the ACL file, add the hass user, and configure rpcd.

```bash
# Copy the script to the router
scp auto-setup.sh root@ROUTER_IP:/root/

# Connect to the router and run it
ssh root@ROUTER_IP
chmod +x auto-setup.sh
./auto-setup.sh
```

Alternatively, you can follow the manual steps below:

* OpenWrt device(s):
  * Make sure that `uhttpd uhttpd-mod-ubus rpcd rpcd-mod-iwinfo` packages are installed (if you use custom images)
  * Make sure that `ubus` is available via http using the manual: <https://openwrt.org/docs/techref/ubus>
    * To make it right, please refer to the `Ubus configuration` section below

* Home Assistant:
  * Add this repo as a custom integration using HACS
  * Restart server
  * Go to `Integrations` and add a new `OpenWrt` integration

### Ubus configuration

* Create new file `/usr/share/rpcd/acl.d/hass.json`:

```jsonc
{
    "hass": {
        "description": "Home Assistant OpenWrt integration permissions",
        "read": {
            "ubus": {
                "network.wireless": ["status"],
                "network.device": ["status"],
                "iwinfo": ["info", "assoclist"],
                "hostapd.*": ["get_clients", "wps_status"],
                "system": ["board", "info"],
                "mwan3": ["status"],
                "luci-rpc": ["getHostHints"],
                "uci": ["get", "configs"]
            },
            "uci": ["wireless"]
        },
        "write": {
            "ubus": {
                "system": ["reboot"],
                "hostapd.*": ["wps_start", "wps_cancel"]
            }
        }
    }
}


```

* Add new system user `hass` (or do it in any other way that you prefer):
  * Add line to `/etc/passwd`: `hass:x:10001:10001:hass:/var:/bin/false`
  * Add line to `/etc/shadow`: `hass:x:0:0:99999:7:::`
  * Change password: `passwd hass`
* Edit `/etc/config/rpcd` and add:

```
config login
        option username 'hass'
        option password '$p$hass'
        list read hass
        list read unauthenticated
        list write hass
```

* Restart rpcd: `/etc/init.d/rpcd restart`

### Executing command

In order to allow ubus/rpcd execute a command remotely, the command should be added to the permissions ACL file above. The extra configuration could look like below (gives permission to execute `uptime` command):

```jsonc
{
  "hass": {
    "write": {
      "ubus": {
        /* ... */
        "file": ["exec"]
      },
      "file": {
        /* ... */
        "/usr/bin/uptime": ["exec"]
      }
    },
  }
}
```

### Manage services using command-line

In order to allow ubus/rpcd execute a command remotely, the command should be added to the permissions ACL file above. The extra configuration could look like below (gives permission to manage `presence-detector` service. Start, stop, restart, enable and disable system services.):

```jsonc
{
  "hass": {
    "write": {
      "ubus": {
        /* ... */
        "rc": ["init"]
      },
      "rc": {
        /* ... */
        "/etc/init.d/presence-detector": ["init"]
      }
    },
  }
}
```

### Screenshots


