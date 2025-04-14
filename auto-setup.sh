#!/bin/sh

# Paso 1: Crear el archivo de permisos ACL para Home Assistant
ACL_FILE="/usr/share/rpcd/acl.d/hass.json"
cat << 'EOF' > "$ACL_FILE"
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
        "uci": ["get"]
      }
    },
    "write": {
      "ubus": {
        "system": ["reboot"],
        "hostapd.*": ["wps_start", "wps_cancel"]
      }
    }
  }
}
EOF

echo "Archivo ACL creado en $ACL_FILE"

# Paso 2: Crear usuario `hass` si no existe
if ! id "hass" >/dev/null 2>&1; then
  echo "Creando usuario hass..."

  echo 'hass:x:10001:10001:hass:/var:/bin/false' >> /etc/passwd
  echo 'hass:x:0:0:99999:7:::' >> /etc/shadow

  echo "Por favor, establece la contraseña para el usuario 'hass':"
  passwd hass
else
  echo "El usuario 'hass' ya existe."
fi

# Paso 3: Añadir configuración de login en /etc/config/rpcd si no existe ya
if ! grep -q "option username 'hass'" /etc/config/rpcd; then
  cat << 'EOF' >> /etc/config/rpcd

config login
        option username 'hass'
        option password '$p$hass'
        list read 'hass'
        list read 'unauthenticated'
        list write 'hass'
EOF

  echo "Se añadió configuración para el usuario 'hass' en /etc/config/rpcd"
else
  echo "La configuración de login para 'hass' ya existe en /etc/config/rpcd"
fi

# Paso 4: Reiniciar rpcd
/etc/init.d/rpcd restart
echo "rpcd reiniciado."

