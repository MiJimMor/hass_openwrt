#!/bin/sh

# --- Language Selection / Selección de Idioma ---
# Choose your preferred language for script output and comments.
# Selecciona tu idioma preferido para la salida del script y los comentarios.
LANG_CHOICE=""
while [ "$LANG_CHOICE" != "es" ] && [ "$LANG_CHOICE" != "en" ]; do
    printf "Choose language (es/en): "
    read -r LANG_CHOICE
done

# Define messages based on selected language
# Definir mensajes basados en el idioma seleccionado
if [ "$LANG_CHOICE" = "es" ]; then
    MSG_PKG_MANAGER_NONE="*** No se encontró un gestor de paquetes compatible (opkg/apk). Se omitió la verificación de paquetes. ***"
    MSG_MISSING_PKGS="*** PAQUETES FALTANTES:"
    MSG_INSTALL_OPKG="Por favor, instálelos en el dispositivo OpenWrt:\n  opkg update && opkg install"
    MSG_INSTALL_APK="Por favor, instálelos en el dispositivo:\n  apk add"
    MSG_ALL_PKGS_INSTALLED="Todos los paquetes requeridos están instalados. (detectado: %s)"
    MSG_ACL_CREATED="Archivo ACL creado en %s"
    MSG_CREATING_USER="Creando usuario hass..."
    MSG_SET_PASS="Por favor, establece la contraseña para el usuario 'hass':"
    MSG_USER_EXISTS="El usuario 'hass' ya existe."
    MSG_CONFIG_ADDED="Se añadió configuración para el usuario 'hass' en /etc/config/rpcd"
    MSG_CONFIG_EXISTS="La configuración de login para 'hass' ya existe en /etc/config/rpcd"
    MSG_RPCD_RESTARTED="rpcd reiniciado."
    MSG_EXIT_MISSING="Saliendo con error porque faltan paquetes."
    MSG_EXIT_CHECK_ONLY="Verificación de paquetes completada."

else # Default to English
    MSG_PKG_MANAGER_NONE="*** No supported package manager found (opkg/apk). Package check skipped. ***"
    MSG_MISSING_PKGS="*** MISSING PACKAGES:"
    MSG_INSTALL_OPKG="Please install them on the OpenWrt device:\n  opkg update && opkg install"
    MSG_INSTALL_APK="Please install them on the device:\n  apk add"
    MSG_ALL_PKGS_INSTALLED="All required packages are installed. (detected: %s)"
    MSG_ACL_CREATED="ACL file created at %s"
    MSG_CREATING_USER="Creating hass user..."
    MSG_SET_PASS="Please set the password for the 'hass' user:"
    MSG_USER_EXISTS="The 'hass' user already exists."
    MSG_CONFIG_ADDED="Configuration for 'hass' user added to /etc/config/rpcd"
    MSG_CONFIG_EXISTS="Login configuration for 'hass' already exists in /etc/config/rpcd"
    MSG_RPCD_RESTARTED="rpcd restarted."
    MSG_EXIT_MISSING="Exiting with error due to missing packages."
    MSG_EXIT_CHECK_ONLY="Package check completed."

fi

# --- Main script logic / Lógica principal del script ---

#"Paso 0: Detectar gestor de paquetes (opkg o apk) y verificar paquetes requeridos"
# "Step 0: Detect package manager (opkg or apk) and check required packages"
REQUIRED_PKGS="uhttpd uhttpd-mod-ubus rpcd rpcd-mod-iwinfo"
PKG_MANAGER="none"
if command -v opkg >/dev/null 2>&1; then
  PKG_MANAGER="opkg"
elif command -v apk >/dev/null 2>&1; then
  PKG_MANAGER="apk"
fi

check_packages() {
    if [ "$PKG_MANAGER" = "none" ]; then
        printf '\n\033[1;31m%s\033[0m\n\n' "$MSG_PKG_MANAGER_NONE"
        return
    fi

    missing=""
    for pkg in $REQUIRED_PKGS; do
        if [ "$PKG_MANAGER" = "opkg" ]; then
            if ! opkg list-installed "$pkg" >/dev/null 2>&1; then
                missing="$missing $pkg"
            fi
        else
            if ! apk info -e "$pkg" >/dev/null 2>&1; then
                missing="$missing $pkg"
            fi
        fi
    done

    if [ -n "$missing" ]; then
        # "Bloque resaltado con fondo rojo para alta visibilidad"
		# "Highlighted block with red background for high visibility"
        printf '\n\033[1;41m%s%s ***\033[0m\n' "$MSG_MISSING_PKGS" "$missing"
        if [ "$PKG_MANAGER" = "opkg" ]; then
            printf '\033[1;33m%s%s\033[0m\n\n' "$MSG_INSTALL_OPKG" "$missing"
        else
            printf '\033[1;33m%s%s\033[0m\n\n' "$MSG_INSTALL_APK" "$missing"
        fi
        return 1 # Indicate missing packages
    else
        #printf '\033[1;32m%s\033[0m\n' "$MSG_ALL_PKGS_INSTALLED" "$PKG_MANAGER"
        printf '\033[1;32m%s\033[0m\n' "$(printf "$MSG_ALL_PKGS_INSTALLED" "$PKG_MANAGER")"
		return 0 # Indicate all packages are installed
    fi
}

# "Comprobar si se pasó el argumento --check-only"
# "Check if --check-only argument was passed"
if [ "$1" = "--check-only" ]; then
    check_packages
    printf '\n%s\n' "$MSG_EXIT_CHECK_ONLY"
    exit 0 # "Exit after checking packages"
fi

# Run package check. Exit if packages are missing for a full setup.
if ! check_packages; then
    printf '\n\033[1;31m%s\033[0m\n' "$MSG_EXIT_MISSING"
    exit 1 # "Exit with error if packages are missing and it's not a check-only run"
fi

# "Paso 1: Crear el archivo de permisos ACL para Home Assistant"
# "Step 1: Create the ACL permissions file for Home Assistant"
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
        "uci": ["get", "configs"]
            },		
      "uci": ["wireless"]
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

printf '\033[1;32m%s\033[0m\n' "$(printf "$MSG_ACL_CREATED" "$ACL_FILE")"

# "Paso 2: Crear usuario `hass` si no existe"
# "Step 2: Create `hass` user if it doesn't exist"
if ! id "hass" >/dev/null 2>&1; then
  printf "\033[1;33m%s\033[0m\n" "$MSG_CREATING_USER"

  echo 'hass:x:10001:10001:hass:/var:/bin/false' >> /etc/passwd
  echo 'hass:x:0:0:99999:7:::' >> /etc/shadow

  printf "\033[1;33m%s\033[0m\n" "$MSG_SET_PASS"
  passwd hass
else
  printf "\033[1;32m%s\033[0m\n" "$MSG_USER_EXISTS"
fi

# "Paso 3: Añadir configuración de login en /etc/config/rpcd si no existe ya"
# "Step 3: Add login configuration to /etc/config/rpcd if it doesn't already exist"
if ! grep -q "option username 'hass'" /etc/config/rpcd; then
  cat << 'EOF' >> /etc/config/rpcd

config login
        option username 'hass'
        option password '$p$hass'
        list read 'hass'
        list read 'unauthenticated'
        list write 'hass'
EOF

  printf "\033[1;33m%s\033[0m\n" "$MSG_CONFIG_ADDED"
else
  printf "\033[1;32m%s\033[0m\n" "$MSG_CONFIG_EXISTS"
fi

# "Step 4: Restart rpcd"
/etc/init.d/rpcd restart
printf "\033[1;36m%s\033[0m\n" "$MSG_RPCD_RESTARTED"