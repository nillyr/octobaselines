# Functions to ease the development of scripts
# shellcheck shell=bash

# Verbose mode. Prints (success|warning|failure) messages
VERBOSE=1
readonly VERBOSE
# Debug mode. Warning: sensitive information may be printed.
DEBUG=0
readonly DEBUG

# Enable encryption
ENABLE_ENCRYPTION=0
readonly ENABLE_ENCRYPTION

AES_KEY_SIZE=32 # in bytes (32=256/8)
readonly AES_KEY_SIZE

AES_IV_SIZE=16 # in bytes
readonly AES_IV_SIZE

# Create the RSA private key: openssl genpkey -out private.key -algorithm RSA -pkeyopt rsa_keygen_bits:4096
# Create a CSR: openssl req -new -key private.key -out certificate.csr
# Sign the CSR: openssl x509 -req -days 365 -in certificate.csr -signkey private.key -out certificate.crt
CERTIFICATE="-----BEGIN CERTIFICATE-----
[...]
-----END CERTIFICATE-----"


msg(){ # args: $1 = tag:str, $2..n = message:str
    local tag="$1"
    shift
    printf "%s [$tag] %s\n" "$(basename "$0")" "$@" >&2
}

# shellcheck disable=SC2317
failure(){ # args: $1 = message:str
    local rc=$?
    local message="$1"
    [ $VERBOSE -eq 1 ] && msg "\e[31mFAIL\e[0m" "$message"
    return "$rc"
}

# shellcheck disable=SC2317
success(){ # args: $1 = message:str
    local message="$1"
    [ "$VERBOSE" -eq 1 ] && msg "\e[32m OK \e[0m" "$message"
    return 0
}

# shellcheck disable=SC2317
debug(){ # args: $1 = message:str
    local message="$1"
    [ "$DEBUG" -eq 1 ] && msg "\e[1;33mDBG \e[0m" "$message"
    return 0
}

# shellcheck disable=SC2317
warning(){ # args: $1 = message:str
    local rc=$?
    local message="$1"
    [ "$VERBOSE" -eq 1 ] && msg "\e[33mWARN\e[0m" "$message"
    return "$rc"
}

# shellcheck disable=SC2317
info(){ # args: $1 = message:str
    local message="$1"
    [ "$VERBOSE" -eq 1 ] && msg "\e[34mINFO\e[0m" "$message"
    return 0
}

# shellcheck disable=SC2317
cleanup(){
    if [[ -n "$BASEDIR" && -d "$BASEDIR" ]]; then
        rm -rf "$BASEDIR" && debug "'$BASEDIR' directory has been removed."
    fi
    exit 1
}

# shellcheck disable=SC2317
identify_distribution(){
    if [ -e /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        case $ID in
            debian)
                DISTRIBUTION=debian
                ;;
            ubuntu)
                DISTRIBUTION=ubuntu
                ;;
            sles)
                DISTRIBUTION=sles
                ;;
            fedora)
                DISTRIBUTION=fedora
                ;;
            rhel)
                DISTRIBUTION=rhel
                ;;
            centos)
                DISTRIBUTION=centos
                ;;
            rocky)
                DISTRIBUTION=rocky
                ;;
            *)
                failure "Unknown or unsupported distribution with ID='$ID'."
                exit 1
                ;;
        esac
    elif command -v rpm >/dev/null && [ -e /etc/redhat-release ]; then
        # Standardizes a set of distributions in rhel
        # RHEL/CentOS, RHEL/Rocky, Fedora, etc.
        DISTRIBUTION=rhel
    else
        failure "Unknown or unsupported distribution."
        exit 1
    fi
}

# shellcheck disable=SC2317
is_package_installed(){ # args: $1 = package:str
    local package="$1"

    if [ -z "$DISTRIBUTION" ]; then
        identify_distribution
    fi

    case $DISTRIBUTION in
        debian|ubuntu)
            if { dpkg -l "${package}" | grep -E "^ii"; } &>/dev/null; then
                debug "'$package' is installed."
                return 0
            else
                debug "'$package' is not installed."
                return 1
            fi
            ;;
        fedora|rhel|centos|rocky|sles)
            if { rpm -q "${package}" ; } &>/dev/null ; then
                debug "'$package' is installed."
                return 0
            else
                debug "'$package' is not installed."
                return 1
            fi
            ;;
        *)
            return 1
            ;;
    esac
}

# shellcheck disable=SC2317
count_available_updates(){ # args: $1 = write_to_stdout:bool
    local write_to_stdout="$1"
    local tmp_output_file
    local count=0
    tmp_output_file=$(mktemp -p /dev/shm/ pkgs.XXXXXXXX)
    is_package_installed sudo && SUDO_CMD="sudo"
    case $DISTRIBUTION in
        debian|ubuntu)
            last=$((1<<62))
            [ -f "/var/cache/apt/pkgcache.bin" ] && last=$(($(date +%s) - $(stat -c '%Y' /var/cache/apt/pkgcache.bin)))
            if ((last >= 28800)); then
                $SUDO_CMD apt-get update &>/dev/null
            fi
            apt-get upgrade -s 2>/dev/null | grep -E "^Inst" > "$tmp_output_file"
            ;;
        fedora|rhel|centos|rocky)
            if is_package_installed dnf; then
                $SUDO_CMD dnf check-update 2>/dev/null > "$tmp_output_file"
            else
                $SUDO_CMD yum check-update 2>/dev/null > "$tmp_output_file"
            fi
            ;;
        sles)
            # zypper list-updates and zypper list-patches are available. lp -> "needed patches"
            $SUDO_CMD zypper list-patches 2>/dev/null > "$tmp_output_file"
            ;;
    esac

    count=$(wc -l "$tmp_output_file" | cut -d' ' -f1)
    debug "Found $count available update(s)."

    [ "$write_to_stdout" == "true" ] && printf "%s\n" "$(cat "$tmp_output_file")"
    rm -f "$tmp_output_file"

    return "$count"
}

# shellcheck disable=SC2317
is_partition_delared(){ # args: $1 = partition:str
    local partition="$1"
    if { findmnt --fstab "$partition"; } &>/dev/null; then
        debug "'$partition' is declared in /etc/fstab."
        return 0
    fi
    debug "'$partition' is not declared in /etc/fstab."
    return 1
}

# shellcheck disable=SC2317
is_partition_declared_with_option(){ # args: $1 = partition:str, $2 = option:str
    local partition="$1"
    local option="$2"
    if { findmnt --fstab "$partition" | grep "$option"; } &>/dev/null; then
        debug "'$partition' is declared with option '$option'."
        return 0
    fi
    debug "'$partition' is not declared with option '$option'."
    return 1
}

# shellcheck disable=SC2317
is_partition_mounted(){ # args: $1 = partition:str
    local partition="$1"
    if { findmnt --mtab "$partition"; } &>/dev/null; then
        debug "'$partition' is mounted."
        return 0
    fi
    debug "'$partition' is not mounted."
    return 1
}

# shellcheck disable=SC2317
is_partition_mounted_with_option(){ # args: $1 = partition:str, $2 = option:str
    local partition="$1"
    local option="$2"
    if { findmnt --mtab "$partition" | grep "$option"; } &>/dev/null; then
        debug "'$partition' is mounted with option '$option'."
        return 0
    else
        debug "'$partition' is not mounted with option '$option'."
        return 1
    fi
}

# shellcheck disable=SC2317
is_dac_setting_correct(){ # args: $1 = file:str, $2 = regex pattern from stat(%A:%U:%G):str
    local file="$1"
    local pattern="$2"

    is_package_installed sudo && SUDO_CMD="sudo"
    if { $SUDO_CMD stat -c "%A:%U:%G" "$file" | grep -E "$pattern"; } &>/dev/null; then
        debug "DAC of file '$file' match with pattern '$pattern'."
        return 0
    fi
    debug "DAC of '$file' does not match with pattern '$pattern'."
    return 1
}

# shellcheck disable=SC2317
init_crypto_material() {
    info "Initialization of the cryptographic material"
    if [ -z "$CERTIFICATE" ] || [ "$AES_KEY_SIZE" != 32 ] || [ "$AES_IV_SIZE" != 16 ]; then
        return 1
    fi

    if ! is_package_installed openssl; then
        return 1
    fi

    info "Generating new AES symmetric-key."
    AES_KEY=$(openssl rand -rand /dev/urandom -hex "$AES_KEY_SIZE")

    info "Saving encrypted version of the AES symmetric-key."
    echo "$CERTIFICATE" > "${BASEDIR}"/certificate.crt
    if ! openssl x509 -in "${BASEDIR}"/certificate.crt -text -noout &>/dev/null; then
        return 1
    fi

    echo "$AES_KEY" | openssl pkeyutl -encrypt -certin -inkey "${BASEDIR}"/certificate.crt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha384 2>/dev/null | base64 > "${BASEDIR}"/aes_key.enc
    file_size=$(stat --printf="%s" "${BASEDIR}"/aes_key.enc)
    if [ "$file_size" -eq 0 ]; then
        return 1
    fi
}

# shellcheck disable=SC2317
encrypt_output() {
    [ "$ENABLE_ENCRYPTION" -eq 0 ] && {
        cat /dev/stdin
        return
    }

    if [ "$AES_KEY_SIZE" != 32 ] || [ "$AES_IV_SIZE" != 16 ]; then
        failure "Critical Error: The specified settings do not allow the use of data encryption. Run the script with 'ENABLE_ENCRYPTION' disabled or check your settings."
        kill -s INT $$
    fi

    AES_IV=$(openssl rand -rand /dev/urandom -hex "$AES_IV_SIZE")
    ENCRYPTED_BYTES_B64=$(openssl enc -e -aes-256-cbc -K "$AES_KEY" -iv "$AES_IV" -base64 < /dev/stdin 2>/dev/null)
    rc=$?
    if [ "$rc" -ne 0 ]; then
        failure "Critical Error: Error while encrypting data. Run the script with 'ENABLE_ENCRYPTION' disabled or check your settings."
        kill -s INT $$
    else
        AES_IV_BYTES_B64=$(echo "$AES_IV" | xxd -r -p | base64)
        FINAL_BLOCK=${AES_IV_BYTES_B64}${ENCRYPTED_BYTES_B64}
        echo "${FINAL_BLOCK//[$'\t\r\n ']}"
    fi
}

# shellcheck disable=SC2317
get_permissions(){  # args: $1..n = file:str
    local files=("$@")

    for file in "${files[@]}"; do
        real_path=$(realpath "$file")
        printf "\nFile: %s\n" "$real_path"
        printf "\n[ Discretionary Access Control (DAC) ]\n"
        stat -c "%n %A:%u:%g" "$real_path"

        printf "\n[ Access Control Lists (ACLs) ]\n"
        getfacl "$real_path"

        printf "\n[ ATTRIBUTES ]\n"
        lsattr "$real_path"

        if [ -d "$real_path" ]; then
	    	ls -ailLZ "$real_path"
		    for child in "$real_path"/*; do
			    get_permissions "$child"
		    done
	    fi
    done
}

# shellcheck disable=SC2317
get_system_info(){
    local hostname=""
    local os=""
    local host=""
    local kernel=""
    local cpu=""
    local gpu=""
    local memory=""
    local ifaces=""

    identify_distribution

    if is_package_installed jq; then
        is_package_installed sudo && SUDO_CMD="sudo"

        hostname="${USER:-$(whoami)}@$($SUDO_CMD lshw -C system -json | jq ".[:1] | .[] | .id" | tr -d '"')"

        host="Host: $($SUDO_CMD lshw -C system -json | jq ".[:1] | .[] | .product" | tr -d '"')"
        host+=" ($($SUDO_CMD lshw -C system -json | jq ".[:1] | .[] | .vendor" | tr -d '"'))"

        gpu="GPU: $($SUDO_CMD lshw -C display -json | jq ".[:1] | .[] | .product" | tr -d '"')"
        gpu+=" ($($SUDO_CMD lshw -C display -json | jq ".[:1] | .[] | .vendor" | tr -d '"'))"
    else
        hostname="${USER:-$(whoami)}@$(hostname -f)"

        host="Host: "
        # https://github.com/dylanaraps/neofetch/blob/master/neofetch#L1238-L1256
        if [[ -d /system/app/ && -d /system/priv-app ]]; then
            host+="$(getprop ro.product.brand) $(getprop ro.product.model)"

        elif [[ -f /sys/devices/virtual/dmi/id/product_name
                && -f /sys/devices/virtual/dmi/id/product_version ]]; then
            host+=$(< /sys/devices/virtual/dmi/id/product_name)
            host+=" $(< /sys/devices/virtual/dmi/id/product_version)"

        elif [[ -f /sys/devices/virtual/dmi/id/board_vendor
                && -f /sys/devices/virtual/dmi/id/board_name ]]; then
            host+=$(< /sys/devices/virtual/dmi/id/board_vendor)
            host+=" $(< /sys/devices/virtual/dmi/id/board_name)"

        elif [[ -f /sys/firmware/devicetree/base/model ]]; then
            host+=$(< /sys/firmware/devicetree/base/model)
        fi

        gpu="GPU:"
        # https://github.com/dylanaraps/neofetch/blob/master/neofetch#L2506-L2517
        gpu_cmd="$(lspci -mm |
                    awk -F '\"|\" \"|\\(' \
                            '/"Display|"3D|"VGA/ {
                                a[$0] = $1 " " $3 " " ($(NF-1) ~ /^$|^Device [[:xdigit:]]+$/ ? $4 : $(NF-1))
                            }
                            END { for (i in a) {
                                if (!seen[a[i]]++) {
                                    sub("^[^ ]+ ", "", a[i]);
                                    print a[i]
                                }
                            }}')"
        gpus=""
        IFS=$'\n' read -d "" -ra gpus <<< "$gpu_cmd"
        gpu+=$gpus
    fi

    if [ -e /etc/lsb-release ]; then
        # shellcheck source=/dev/null
        . /etc/lsb-release
    fi
    if [ -e /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
    fi

    os="OS: $(uname -o) ${PRETTY_NAME:-${DISTRIB_DESCRIPTION}} $(uname -m)"
    kernel="Kernel: $(uname -r)"
    cpu="CPU: $(grep "model name" /proc/cpuinfo | awk -F ": " '{print $NF}' | head -n1) ($(nproc --all))"
    memory="Memory: $(grep -i "MemTotal" /proc/meminfo | awk '{$2/=1024;printf "%.2f MB",$2}')"

    ifaces="Network: [ "
    for iface in "/sys/class/net"/*; do
        iface=$(basename "$iface")
        if is_package_installed iproute2; then
            ifaces+="$iface: $(ip -4 -o addr show "$iface" 2>/dev/null | awk '{print $4}'), "
        else
            ifaces+="$iface: $(ifconfig "$iface" 2>/dev/null | grep 'inet addr:' | cut -d: -f2| cut -d' ' -f1), "
        fi
    done
    ifaces+="]"

    printf "%s\n" "$hostname"
    printf "%s\n" "--------------------------"
    printf "%s\n" "$os"
    printf "%s\n" "$host"
    printf "%s\n" "$kernel"
    printf "%s\n" "$cpu"
    printf "%s\n" "$gpu"
    printf "%s\n" "$memory"
    printf "%s\n" "$ifaces"
}

# shellcheck disable=SC2317
assert_user_privileges() {
    if [ "${EUID}" -eq 0 ]; then
        return 0
    fi

    is_package_installed sudo && SUDO_CMD="sudo"
    if $SUDO_CMD -l &>/dev/null; then
        return 0
    fi

    return 1
}

trap cleanup SIGHUP SIGINT SIGQUIT SIGABRT

if [ ! "$(uname -s)" == "Linux" ]; then
    failure "This script must be run on Linux."
    exit 1
fi

if ! assert_user_privileges; then
    failure "'${USER}' does not have enough privileges to run this script."
    exit 1
fi

# This should never happen, but we never know.
# reason: this file is integrated in the generated script, which must initialize the variable.
if [ -z "$BASEDIR" ]; then
    BASEDIR=$(mktemp -d -t tmp.XXXXXXXXXXXX)
    info "A working directory has been created in $BASEDIR."
fi

if [ "$ENABLE_ENCRYPTION" -eq 1 ]; then
    if ! init_crypto_material; then
        failure "Critical Error: The specified settings do not allow the use of data encryption. Run the script with 'ENABLE_ENCRYPTION' disabled or check your settings."
        kill -s INT $$
    fi
fi

get_system_info | encrypt_output > "${BASEDIR}"/system_information.txt
