#!/bin/sh

#set -x

# Глобальная переменная для хранения списка созданных интерфейсов
CONFIGURED_INTERFACES=""

###
# 1. СИСТЕМНЫЕ ФУНКЦИИ
###

# Проверка доступности репозиториев OpenWrt
check_repo() {
    printf "\033[32;1mChecking OpenWrt repo availability...\033[0m\n"
    opkg update |
    grep -q "Failed to download" && printf "\033[32;1mopkg failed. Check internet or date. Command for force ntp sync: ntpd -p ptbtime1.ptb.de\033[0m\n" && exit 1
}

# Установка базовых пакетов (curl, nano)
add_packages() {
    for package in curl nano;
    do
        if opkg list-installed | grep -q "^$package ";
        then
            printf "\033[32;1m$package already installed\033[0m\n"
        else
            printf "\033[32;1mInstalling $package...\033[0m\n"
            opkg install "$package"
            
            if "$package" --version >/dev/null 2>&1;
            then
                printf "\033[32;1m$package was successfully installed and available\033[0m\n"
            else
                printf "\031;1mError: failed to install $package\033[0m\n"
                exit 1
            fi
        fi
    done
}

# Установка пакетов Amnezia WireGuard (AWG)
# Логика извлечена из оригинального скрипта [cite: 145-155]
install_awg_packages() {
    printf "\033[32;1mInstalling Amnezia WireGuard packages...\033[0m\n"

    # Проверка, установлены ли уже пакеты
    if opkg list-installed | grep -q "amneziawg-tools" && \
       opkg list-installed | grep -q "kmod-amneziawg" && \
       opkg list-installed | grep -q "luci-app-amneziawg"; then
        printf "\033[32;1mAmneziaWG packages already installed.\033[0m\n"
        return 0
    fi

    # Получение архитектуры пакетов [cite: 145, 146]
    PKGARCH=$(opkg print-architecture | awk 'BEGIN {max=0} {if ($3 > max) {max = $3; arch = $2}} END {print arch}')
    TARGET=$(ubus call system board | jsonfilter -e '@.release.target' | cut -d '/' -f 1)
    SUBTARGET=$(ubus call system board | jsonfilter -e '@.release.target' | cut -d '/' -f 2)
    VERSION=$(ubus call system board | jsonfilter -e '@.release.version')
    PKGPOSTFIX="_v${VERSION}_${PKGARCH}_${TARGET}_${SUBTARGET}.ipk"
    BASE_URL="https://github.com/Slava-Shchipunov/awg-openwrt/releases/download/"
    AWG_DIR="/tmp/amneziawg"

    mkdir -p "$AWG_DIR"

    # Пакеты для установки
    packages="amneziawg-tools kmod-amneziawg luci-app-amneziawg"

    for pkg in $packages; do
        if opkg list-installed | grep -q "$pkg"; then
            echo "$pkg already installed"
            continue
        fi

        FILENAME="${pkg}${PKGPOSTFIX}"
        DOWNLOAD_URL="${BASE_URL}v${VERSION}/${FILENAME}"
        
        printf "Downloading $FILENAME...\n"
        curl -L -o "$AWG_DIR/$FILENAME" "$DOWNLOAD_URL"
        if [ $? -ne 0 ]; then
            printf "\033[31;1mError downloading $pkg. Please install manually.\033[0m\n"
            rm -rf "$AWG_DIR"
            exit 1
        fi

        printf "Installing $pkg...\n"
        opkg install "$AWG_DIR/$FILENAME"
        if [ $? -ne 0 ]; then
            printf "\033[31;1mError installing $pkg. Please install manually.\033[0m\n"
            rm -rf "$AWG_DIR"
            exit 1
        fi
    done

    rm -rf "$AWG_DIR"
    printf "\033[32;1mAmneziaWG packages installed successfully.\033[0m\n"
}

###
# 2. КОНФИГУРАЦИЯ VPN И FAILOVER
###

# Главная функция настройки туннелей AWG
# Поддерживает несколько серверов и настраивает failover
configure_awg_servers() {
    # Сначала убедимся, что пакеты AWG установлены
    install_awg_packages

    local SERVER_INDEX=0
    local INTERFACE_LIST=""

    while true; do
        local INTERFACE_NAME="awg${SERVER_INDEX}"
        local CONFIG_NAME="amneziawg_${INTERFACE_NAME}"
        # Рассчитываем метрику: awg0 -> 10, awg1 -> 20, и т.д.
        local METRIC=$((10 * (SERVER_INDEX + 1)))

        printf "\n\033[34;1m--- Configuring AWG Server $SERVER_INDEX (Interface: $INTERFACE_NAME, Metric: $METRIC) ---\033[0m\n"

        # Сбор данных от пользователя [логика из [cite: 42-46]]
        read -r -p "Enter the private key (from [Interface]):"$'\n' AWG_PRIVATE_KEY
        
        local AWG_IP
        while true; do
            read -r -p "Enter internal IP address with subnet (e.g., 192.168.100.5/24) (from [Interface]):"$'\n' AWG_IP
            if echo "$AWG_IP" | egrep -oq '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$'; then
                break
            else
                echo "This IP is not valid. Please repeat"
            fi
        done

        read -r -p "Enter Jc value (from [Interface]):"$'\n' AWG_JC
        read -r -p "Enter Jmin value (from [Interface]):"$'\n' AWG_JMIN
        read -r -p "Enter Jmax value (from [Interface]):"$'\n' AWG_JMAX
        read -r -p "Enter S1 value (from [Interface]):"$'\n' AWG_S1
        read -r -p "Enter S2 value (from [Interface]):"$'\n' AWG_S2
        read -r -p "Enter H1 value (from [Interface]):"$'\n' AWG_H1
        read -r -p "Enter H2 value (from [Interface]):"$'\n' AWG_H2
        read -r -p "Enter H3 value (from [Interface]):"$'\n' AWG_H3
        read -r -p "Enter H4 value (from [Interface]):"$'\n' AWG_H4
    
        read -r -p "Enter the public key (from [Peer]):"$'\n' AWG_PUBLIC_KEY
        read -r -p "If use PresharedKey, Enter this (from [Peer]). If your don't use leave blank:"$'\n' AWG_PRESHARED_KEY
        read -r -p "Enter Endpoint host without port (Domain or IP) (from [Peer]):"$'\n' AWG_ENDPOINT

        read -r -p "Enter Endpoint host port (from [Peer]) [51820]:"$'\n' AWG_ENDPOINT_PORT
        AWG_ENDPOINT_PORT=${AWG_ENDPOINT_PORT:-51820}

        # Настройка интерфейса [логика из [cite: 47, 48]]
        uci set network.${INTERFACE_NAME}=interface
        uci set network.${INTERFACE_NAME}.proto='amneziawg'
        uci set network.${INTERFACE_NAME}.private_key=$AWG_PRIVATE_KEY
        uci set network.${INTERFACE_NAME}.listen_port="5182${SERVER_INDEX}" # Уникальный порт для каждого
        uci set network.${INTERFACE_NAME}.addresses="$AWG_IP"

        uci set network.${INTERFACE_NAME}.awg_jc=$AWG_JC
        uci set network.${INTERFACE_NAME}.awg_jmin=$AWG_JMIN
        uci set network.${INTERFACE_NAME}.awg_jmax=$AWG_JMAX
        uci set network.${INTERFACE_NAME}.awg_s1=$AWG_S1
        uci set network.${INTERFACE_NAME}.awg_s2=$AWG_S2
        uci set network.${INTERFACE_NAME}.awg_h1=$AWG_H1
        uci set network.${INTERFACE_NAME}.awg_h2=$AWG_H2
        uci set network.${INTERFACE_NAME}.awg_h3=$AWG_H3
        uci set network.${INTERFACE_NAME}.awg_h4=$AWG_H4

        # Настройка пира (peer) [логика из [cite: 49, 50]]
        if ! uci show network | grep -q "amneziawg_${INTERFACE_NAME}"; then
            uci add network amneziawg_${INTERFACE_NAME}
        fi
        uci set network.@amneziawg_${INTERFACE_NAME}[0]=amneziawg_${INTERFACE_NAME}
        uci set network.@amneziawg_${INTERFACE_NAME}[0].name="${INTERFACE_NAME}_client"
        uci set network.@amneziawg_${INTERFACE_NAME}[0].public_key=$AWG_PUBLIC_KEY
        uci set network.@amneziawg_${INTERFACE_NAME}[0].preshared_key=$AWG_PRESHARED_KEY
        uci set network.@amneziawg_${INTERFACE_NAME}[0].route_allowed_ips='0'
        uci set network.@amneziawg_${INTERFACE_NAME}[0].persistent_keepalive='25'
        uci set network.@amneziawg_${INTERFACE_NAME}[0].endpoint_host=$AWG_ENDPOINT
        uci set network.@amneziawg_${INTERFACE_NAME}[0].allowed_ips='0.0.0.0/0'
        uci set network.@amneziawg_${INTERFACE_NAME}[0].endpoint_port=$AWG_ENDPOINT_PORT

        # **РЕАЛИЗАЦИЯ FAILOVER**
        # Добавляем статический маршрут в таблицу 'vpn' с уникальной метрикой
        # netifd (сетевой демон OpenWrt) автоматически добавит этот маршрут,
        # когда интерфейс $INTERFACE_NAME будет поднят, и удалит, когда он упадет.
        # Ядро автоматически выберет маршрут с наименьшей доступной метрикой.
        printf "\033[32;1mAdding failover route for $INTERFACE_NAME with metric $METRIC...\033[0m\n"
        uci add network route
        uci set network.@route[-1].name="vpn_route_${INTERFACE_NAME}"
        uci set network.@route[-1].interface="${INTERFACE_NAME}"
        uci set network.@route[-1].target='0.0.0.0'
        uci set network.@route[-1].netmask='0.0.0.0'
        uci set network.@route[-1].table='vpn'
        uci set network.@route[-1].metric="${METRIC}"
        
        uci commit network

        # Сохраняем имя интерфейса для настройки firewall
        INTERFACE_LIST="${INTERFACE_LIST} ${INTERFACE_NAME}"

        SERVER_INDEX=$((SERVER_INDEX + 1))

        # Запрос на добавление следующего сервера
        local ADD_MORE
        read -r -p "Add another AmneziaWG server? (y/N): " ADD_MORE
        case $ADD_MORE in
            [yY] | [yY][eE][sS])
                continue
                ;;
            *)
                break
                ;;
        esac
    done

    # Возвращаем список всех созданных интерфейсов
    echo "$INTERFACE_LIST"
}

###
# 3. НАСТРОЙКА МАРШРУТИЗАЦИИ И FIREWALL
###

# Добавление таблицы 'vpn' и правила маркировки
# (Оригинальная функция add_mark)
add_policy_routing_rule() {
    # Добавляем таблицу 'vpn', если ее нет 
    grep -q "99 vpn" /etc/iproute2/rt_tables ||
    echo '99 vpn' >> /etc/iproute2/rt_tables
    
    # Добавляем правило, которое отправляет пакеты с меткой 0x1 в таблицу 'vpn' 
    if ! uci show network | grep -q mark0x1; then
        printf "\033[32;1mConfigure mark rule (0x1 -> table vpn)\033[0m\n"
        uci add network rule
        uci set network.@rule[-1].name='mark0x1'
        uci set network.@rule[-1].mark='0x1'
        uci set network.@rule[-1].priority='100'
        uci set network.@rule[-1].lookup='vpn'
        uci commit network
    fi
}

# Настройка Firewall Zone
# Создает *одну* зону 'vpn_awg' и добавляет в нее *все* наши AWG интерфейсы
configure_firewall_zone() {
    local INTERFACE_LIST="$1"
    local ZONE_NAME="vpn_awg" # Единое имя зоны

    if [ -z "$INTERFACE_LIST" ]; then
        printf "\033[33;1mNo interfaces configured. Skipping firewall zone.\033[0m\n"
        return
    fi

    printf "\033[32;1mConfiguring firewall zone '$ZONE_NAME' for interfaces: $INTERFACE_LIST\033[0m\n"

    # Очистка старых зон и правил (гигиена из старого скрипта) [cite: 58-80]
    for old_zone in wg0 awg0 tun0 ovpn singbox tun2socks; do
        zone_id=$(uci show firewall | grep -E "@zone.*($old_zone|'$old_zone')" | awk -F '[][{}]' '{print $2}' | head -n 1)
        if [ ! -z "$zone_id" ]; then
            printf "Cleaning up old zone: $old_zone (ID: $zone_id)...\n"
            while uci -q delete firewall.@zone[$zone_id]; do :; done
        fi
    done
    for old_dest in wg awg ovpn singbox tun2socks; do
        forward_id=$(uci show firewall | grep -E "@forwarding.*dest='$old_dest'" | awk -F '[][{}]' '{print $2}' | head -n 1)
        if [ ! -z "$forward_id" ]; then
             printf "Cleaning up old forwarding for: $old_dest (ID: $forward_id)...\n"
            while uci -q delete firewall.@forwarding[$forward_id]; do :; done
        fi
    done
    
    # Создаем *одну* новую зону
    uci add firewall zone
    uci set firewall.@zone[-1].name="$ZONE_NAME"
    uci set firewall.@zone[-1].forward='REJECT'
    uci set firewall.@zone[-1].output='ACCEPT'
    uci set firewall.@zone[-1].input='REJECT'
    uci set firewall.@zone[-1].masq='1'
    uci set firewall.@zone[-1].mtu_fix='1'
    uci set firewall.@zone[-1].family='ipv4'

    # Добавляем *все* наши интерфейсы в эту зону
    for iface in $INTERFACE_LIST; do
        uci add_list firewall.@zone[-1].network="$iface"
    done

    # Создаем *одно* правило проброса из lan в нашу новую зону
    uci add firewall forwarding
    uci set firewall.@forwarding[-1]=forwarding
    uci set firewall.@forwarding[-1].name="${ZONE_NAME}-lan"
    uci set firewall.@forwarding[-1].dest="$ZONE_NAME"
    uci set firewall.@forwarding[-1].src='lan'
    uci set firewall.@forwarding[-1].family='ipv4'
    
    uci commit firewall
}

###
# 4. НАСТРОЙКА DNS И СПИСКОВ ДОМЕНОВ
###

# Установка dnsmasq-full (для поддержки ipset)
dnsmasqfull() {
    if opkg list-installed | grep -q dnsmasq-full; then
        printf "\033[32;1mdnsmasq-full already installed\033[0m\n"
    else
        printf "\033[32;1mInstalling dnsmasq-full...\033[0m\n"
        cd /tmp/ && opkg download dnsmasq-full
        opkg remove dnsmasq && opkg install dnsmasq-full --cache /tmp/
        [ -f /etc/config/dhcp-opkg ] && cp /etc/config/dhcp /etc/config/dhcp-old && mv /etc/config/dhcp-opkg /etc/config/dhcp
    fi
}

# Настройка confdir для dnsmasq
dnsmasqconfdir() {
    if [ $VERSION_ID -ge 24 ]; then
        if uci get dhcp.@dnsmasq[0].confdir | grep -q /tmp/dnsmasq.d; then
            printf "\033[32;1mconfdir already set\033[0m\n"
        else
            printf "\033[32;1mSetting confdir\033[0m\n"
            uci set dhcp.@dnsmasq[0].confdir='/tmp/dnsmasq.d'
            uci commit dhcp
        fi
    fi
}

# Создание ipset и правила firewall для маркировки пакетов
add_ipset_rule() {
    # Создаем ipset 'vpn_domains', куда dnsmasq будет класть IP 
    if uci show firewall | grep -q "@ipset.*name='vpn_domains'"; then
        printf "\033[32;1mSet 'vpn_domains' already exist\033[0m\n"
    else
        printf "\033[32;1mCreate set 'vpn_domains'\033[0m\n"
        uci add firewall ipset
        uci set firewall.@ipset[-1].name='vpn_domains'
        uci set firewall.@ipset[-1].match='dst_net'
        uci commit firewall
    fi
    
    # Создаем правило, которое ищет IP назначения в 'vpn_domains' и ставит метку 0x1 [cite: 85, 86]
    if uci show firewall | grep -q "@rule.*name='mark_domains'"; then
        printf "\033[32;1mRule 'mark_domains' for set already exist\033[0m\n"
    else
        printf "\033[32;1mCreate rule 'mark_domains'\033[0m\n"
        uci add firewall rule
        uci set firewall.@rule[-1]=rule
        uci set firewall.@rule[-1].name='mark_domains'
        uci set firewall.@rule[-1].src='lan'
        uci set firewall.@rule[-1].dest='*'
        uci set firewall.@rule[-1].proto='all'
        uci set firewall.@rule[-1].ipset='vpn_domains'
        uci set firewall.@rule[-1].set_mark='0x1'
        uci set firewall.@rule[-1].target='MARK'
        uci set firewall.@rule[-1].family='ipv4'
        uci commit firewall
    fi
}

# (Опционально) Настройка DNS-over-TLS/HTTPS
add_dns_resolver() {
    echo "Configure DNSCrypt2 or Stubby? (Recommended if ISP spoofs DNS)"
    DISK=$(df -m / | awk 'NR==2{ print $2 }')
    if [[ "$DISK" -lt 32 ]]; then 
        printf "\033[31;1mYour router a disk have less than 32MB. DNSCrypt (10MB) is not recommended.\033[0m\n"
    fi
    echo "Select:"
    echo "1) No [Default]"
    echo "2) DNSCrypt2 (10.7M)"
    echo "3) Stubby (36K)"

    local DNS_RESOLVER
    while true; do
        read -r -p '' DNS_RESOLVER
        case $DNS_RESOLVER in 
            "" | 1) echo "Skipped"; break ;;
            2) DNS_RESOLVER=DNSCRYPT; break ;;
            3) DNS_RESOLVER=STUBBY; break ;;
            *) echo "Choose from 1, 2, or 3" ;;
        esac
    done

    if [ "$DNS_RESOLVER" == 'DNSCRYPT' ]; then
        # ... (логика установки DNSCrypt без изменений) [cite: 93-98] ...
        if opkg list-installed | grep -q dnscrypt-proxy2; then
            printf "\033[32;1mDNSCrypt2 already installed\033[0m\n"
        else
            printf "\033[32;1mInstalled dnscrypt-proxy2\033[0m\n"
            opkg install dnscrypt-proxy2
            if grep -q "# server_names" /etc/dnscrypt-proxy2/dnscrypt-proxy.toml; then
                sed -i "s/^# server_names =.*/server_names = [\'google\', \'cloudflare\', \'scaleway-fr\', \'yandex\']/g" /etc/dnscrypt-proxy2/dnscrypt-proxy.toml
            fi
            service dnscrypt-proxy restart
            printf "\033[32;1mDNSCrypt needs to load the relays list. Please wait 30s...\033[0m\n"
            sleep 30
            if [ -f /etc/dnscrypt-proxy2/relays.md ]; then
                uci set dhcp.@dnsmasq[0].noresolv="1"
                uci -q delete dhcp.@dnsmasq[0].server
                uci add_list dhcp.@dnsmasq[0].server="127.0.0.53#53"
                uci add_list dhcp.@dnsmasq[0].server='/use-application-dns.net/'
                uci commit dhcp
                /etc/init.d/dnsmasq restart
            else
                printf "\033[31;1mDNSCrypt not download list. Repeat install DNSCrypt by script.\033[0m\n"
            fi
        fi
    fi

    if [ "$DNS_RESOLVER" == 'STUBBY' ]; then
        # ... (логика установки Stubby без изменений) [cite: 100-102] ...
         if opkg list-installed | grep -q stubby; then
            printf "\033[32;1mStubby already installed\033[0m\n"
        else
            printf "\033[32;1mInstalled stubby\033[0m\n"
            opkg install stubby
            uci set dhcp.@dnsmasq[0].noresolv="1"
            uci -q delete dhcp.@dnsmasq[0].server
            uci add_list dhcp.@dnsmasq[0].server="127.0.0.1#5453"
            uci add_list dhcp.@dnsmasq[0].server='/use-application-dns.net/'
            uci commit dhcp
            /etc/init.d/dnsmasq restart
        fi
    fi
}

# Настройка скрипта getdomains для заполнения ipset
add_getdomains() {
    # ... (логика выбора страны и создания /etc/init.d/getdomains без изменений) [cite: 106-122] ...
    local COUNTRY EOF_DOMAINS
    echo "Choose domain list for VPN routing"
    echo "Select:"
    echo "1) Russia inside. You are inside Russia (route foreign sites)"
    echo "2) Russia outside. You are outside Russia (route Russian sites)"
    echo "3) Ukraine. uablacklist.net list"
    echo "4) Skip script creation"

    while true; do
        read -r -p '' COUNTRY
        case $COUNTRY in 
            1) COUNTRY=russia_inside; break ;;
            2) COUNTRY=russia_outside; break ;;
            3) COUNTRY=ukraine; break ;;
            4) echo "Skipped"; COUNTRY=0; break ;;
            *) echo "Choose from 1-4" ;;
        esac
    done

    if [ "$COUNTRY" == 'russia_inside' ]; then
        EOF_DOMAINS='DOMAINS=https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-dnsmasq-nfset.lst'
    elif [ "$COUNTRY" == 'russia_outside' ]; then
        EOF_DOMAINS='DOMAINS=https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/outside-dnsmasq-nfset.lst'
    elif [ "$COUNTRY" == 'ukraine' ]; then
        EOF_DOMAINS='DOMAINS=https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Ukraine/inside-dnsmasq-nfset.lst'
    fi

    if [ "$COUNTRY" != '0' ]; then
        printf "\033[32;1mCreate script /etc/init.d/getdomains\033[0m\n"
cat << EOF > /etc/init.d/getdomains
#!/binsh /etc/rc.common
START=99
start () {
    $EOF_DOMAINS
    count=0
    while true; do
        if curl -m 3 github.com; then
            curl -f \$DOMAINS --output /tmp/dnsmasq.d/domains.lst
            break
        else
            echo "GitHub is not available. Check the internet availability [\$count]"
            count=\$((count+1))
        fi
    done
    if dnsmasq --conf-file=/tmp/dnsmasq.d/domains.lst --test 2>&1 | grep -q "syntax check OK"; then
        /etc/init.d/dnsmasq restart
    fi
}
EOF
        chmod +x /etc/init.d/getdomains
        /etc/init.d/getdomains enable
        if ! crontab -l | grep -q /etc/init.d/getdomains; then
            crontab -l | { cat; echo "0 */8 * * * /etc/init.d/getdomains start"; } | crontab -
            /etc/init.d/cron restart
        fi
        printf "\033[32;1mStart script to fetch domains...\033[0m\n"
        /etc/init.d/getdomains start
    fi
}

###
# 5. ОСНОВНОЙ ПОТОК ВЫПОЛНЕНИЯ
###

# Системная информация и проверка версии
MODEL=$(cat /tmp/sysinfo/model)
source /etc/os-release
printf "\033[34;1mModel: $MODEL\033[0m\n"
printf "\033[34;1mVersion: $OPENWRT_RELEASE\033[0m\n"

VERSION_ID=$(echo $VERSION | awk -F. '{print $1}')
if [ "$VERSION_ID" -ne 23 ] && [ "$VERSION_ID" -ne 24 ]; then
    printf "\033[31;1mScript only support OpenWrt 23.05 and 24.10\033[0m\n"
    exit 1
fi

printf "\033[31;1mAll actions performed here cannot be rolled back automatically.\033[0m\n"
read -r -p "Press Enter to continue, or Ctrl+C to abort."

# --- Шаги установки ---

# 1. Проверка репо
check_repo

# 2. Установка базовых утилит
add_packages

# 3. Установка DNS (для ipset)
dnsmasqfull
dnsmasqconfdir

# 4. Настройка VPN туннелей (цикл) и маршрутов Failover
# Сохраняем список созданных интерфейсов в переменную
CONFIGURED_INTERFACES=$(configure_awg_servers)

# 5. Настройка таблицы 'vpn' и правила маркировки 0x1
add_policy_routing_rule

# 6. Настройка Firewall (одна зона для всех туннелей)
configure_firewall_zone "$CONFIGURED_INTERFACES"

# 7. Настройка ipset 'vpn_domains' и правила маркировки firewall
add_ipset_rule

# 8. (Опционально) Настройка безопасного DNS
add_dns_resolver

# 9. (Опционально) Настройка скрипта получения доменов
add_getdomains

# --- Завершение ---
printf "\033[32;1mRestarting network and services...\033[0m\n"
/etc/init.d/network restart
/etc/init.d/firewall restart
/etc/init.d/dnsmasq restart

printf "\033[32;1mDone. Configuration complete.\033[0m\n"