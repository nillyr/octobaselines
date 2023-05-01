# Functions to ease the development of scripts
# shellcheck shell=bash

# Verbose mode. Prints (success|warning|failure) messages
VERBOSE=1
readonly VERBOSE
# Debug mode. Warning: sensitive information may be printed.
DEBUG=1
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
    printf "%s [${tag}] %s\n" "$(basename "$0")" "$@" >&2
}

# shellcheck disable=SC2317
failure(){ # args: $1 = message:str
    local rc=$?
    local message="$1"
    [ "${VERBOSE}" -eq 1 ] && msg "\e[31mFAIL\e[0m" "${message}"
    return "$rc"
}

# shellcheck disable=SC2317
success(){ # args: $1 = message:str
    local message="$1"
    [ "${VERBOSE}" -eq 1 ] && msg "\e[32m OK \e[0m" "${message}"
    return 0
}

# shellcheck disable=SC2317
debug(){ # args: $1 = message:str
    local message="$1"
    [ "${DEBUG}" -eq 1 ] && msg "\e[1;33mDBG \e[0m" "${message}"
    return 0
}

# shellcheck disable=SC2317
warning(){ # args: $1 = message:str
    local rc=$?
    local message="$1"
    [ "${VERBOSE}" -eq 1 ] && msg "\e[33mWARN\e[0m" "${message}"
    return "$rc"
}

# shellcheck disable=SC2317
info(){ # args: $1 = message:str
    local message="$1"
    [ "${VERBOSE}" -eq 1 ] && msg "\e[34mINFO\e[0m" "${message}"
    return 0
}

# shellcheck disable=SC2317
cleanup(){
    if [[ -n "${BASEDIR}" && -d "${BASEDIR}" ]]; then
        rm -rf "${BASEDIR}" && debug "'${BASEDIR}' directory has been removed."
    fi
    exit 1
}

# shellcheck disable=SC2317
identify_distribution(){
    if [ -e /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        case ${ID} in
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
                failure "Unknown or unsupported distribution with ID='${ID}'."
                exit 1
                ;;
        esac
    elif command -v rpm &>/dev/null && [ -e /etc/redhat-release ]; then
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

    if [ -z "${DISTRIBUTION}" ]; then
        identify_distribution
    fi

    case ${DISTRIBUTION} in
        debian|ubuntu)
            if { dpkg -l "${package}" | grep -E "^ii"; } &>/dev/null; then
                debug "'${package}' is installed."
                return 0
            else
                debug "'${package}' is not installed."
                return 1
            fi
            ;;
        fedora|rhel|centos|rocky|sles)
            if { rpm -q "${package}" ; } &>/dev/null ; then
                debug "'${package}' is installed."
                return 0
            else
                debug "'${package}' is not installed."
                return 1
            fi
            ;;
        *)
            return 1
            ;;
    esac
}

# shellcheck disable=SC2317
get_pkg_version(){ # args: $1 = package
    local package="$1"

    if [ -z "${DISTRIBUTION}" ]; then
        identify_distribution
    fi

    pkg_version=""
    case ${DISTRIBUTION} in
        debian|ubuntu)
            pkg_version=$(dpkg -s "${package}" | grep -E "^\s*Version\s*:" | awk -F ":" '{print $NF}' | tr -d ' ')
            ;;
        fedora|rhel|centos|rocky)
            pkg_version=$(rpm -qi "${package}" | grep -E "^\s*Version\s*:" | awk -F ":" '{print $NF}' | tr -d ' ')
            ;;
        sles)
            pkg_version=$(zypper info "${package}" | grep -E "^\s*Version\s*:" | awk -F ":" '{print $NF}' | tr -d ' ')
            ;;
        *)
            ;;
    esac

    echo "${pkg_version}"
}

# shellcheck disable=SC2317
get_installation_date_of_pkg(){ # args: $1 = package, $2 = full_details: bool
    local package="$1"
    local full_details="$2"

    is_package_installed sudo && SUDO_CMD="sudo"
    case ${DISTRIBUTION} in
        debian|ubuntu)
            if [[ "${full_details}" == "true" ]]; then
                installation_date=$(${SUDO_CMD} zgrep "install ${package}" /var/log/dpkg.log* 2>/dev/null | cut -f1,2,4 -d' ')
            else
                installation_date=$(${SUDO_CMD} zgrep "install ${package}" /var/log/dpkg.log* 2>/dev/null | cut -f1,2 -d' ' | awk -F ":" '{ for(i=2; i<=NF; i++) printf "%s%s", (i == 2 ? $i : ":"$i ), (i < NF ? "" : ORS) }')
            fi
            ;;
        fedora|rhel|centos|rocky|sles)
            if [[ "${full_details}" == "true" ]]; then
                installation_date=$(${SUDO_CMD} rpm -qi "${package}" 2>/dev/null | grep "Install Date: ")
            else
                installation_date=$(${SUDO_CMD} rpm -qi "${package}" 2>/dev/null | grep "Install Date: " | awk -F ":" '{ for(i=2; i<=NF; i++) printf "%s%s", (i == 2 ? $i : ":"$i ), (i < NF ? "" : ORS) }')
            fi
            ;;
        *)
            ;;
    esac

    echo "${installation_date}"
}

# shellcheck disable=SC2317
count_available_updates(){ # args: $1 = write_to_stdout:bool
    local write_to_stdout="$1"
    local tmp_output_file=""
    local count=0
    tmp_output_file=$(mktemp -p /dev/shm/ pkgs.XXXXXXXX)
    is_package_installed sudo && SUDO_CMD="sudo"
    case ${DISTRIBUTION} in
        debian|ubuntu)
            last=$((1<<62))
            [ -f "/var/cache/apt/pkgcache.bin" ] && last=$(($(date +%s) - $(stat -c '%Y' /var/cache/apt/pkgcache.bin)))
            # 28800 seconds = 8 hours
            if ((last >= 28800)); then
                ${SUDO_CMD} apt update &>/dev/null
            fi
            apt upgrade -s 2>/dev/null | grep -E "^Inst" > "${tmp_output_file}"
            ;;
        fedora|rhel|centos|rocky)
            if is_package_installed dnf; then
                ${SUDO_CMD} dnf check-update 2>/dev/null > "${tmp_output_file}"
            else
                ${SUDO_CMD} yum check-update 2>/dev/null > "${tmp_output_file}"
            fi
            ;;
        sles)
            ${SUDO_CMD} zypper list-patches 2>/dev/null > "${tmp_output_file}"
            ;;
    esac

    case ${DISTRIBUTION} in
        sles)
            # regex "xx patches needed (yy security patches)" on the last line
            count=$(tail --lines 1 "${tmp_output_file}" | grep -Eo "^[0-9]*")
            ;;
        *)
            count=$(wc -l "${tmp_output_file}" | cut -d' ' -f1)
            ;;
    esac

    debug "Found ${count} available update(s)."

    [ "${write_to_stdout}" == "true" ] && printf "%s\n" "$(cat "${tmp_output_file}")"
    rm -f "${tmp_output_file}"

    return "${count}"
}

# shellcheck disable=SC2317
is_partition_delared(){ # args: $1 = partition:str
    local partition="$1"
    if { findmnt --fstab "${partition}"; } &>/dev/null; then
        debug "'${partition}' is declared in /etc/fstab."
        return 0
    fi
    debug "'${partition}' is not declared in /etc/fstab."
    return 1
}

# shellcheck disable=SC2317
is_partition_declared_with_option(){ # args: $1 = partition:str, $2 = option:str
    local partition="$1"
    local option="$2"
    if { findmnt --fstab "${partition}" | grep "${option}"; } &>/dev/null; then
        debug "'${partition}' is declared with option '${option}'."
        return 0
    fi
    debug "'${partition}' is not declared with option '${option}'."
    return 1
}

# shellcheck disable=SC2317
is_partition_mounted(){ # args: $1 = partition:str
    local partition="$1"
    if { findmnt --mtab "${partition}"; } &>/dev/null; then
        debug "'${partition}' is mounted."
        return 0
    fi
    debug "'${partition}' is not mounted."
    return 1
}

# shellcheck disable=SC2317
is_partition_mounted_with_option(){ # args: $1 = partition:str, $2 = option:str
    local partition="$1"
    local option="$2"
    if { findmnt --mtab "${partition}" | grep "${option}"; } &>/dev/null; then
        debug "'${partition}' is mounted with option '${option}'."
        return 0
    else
        debug "'${partition}' is not mounted with option '${option}'."
        return 1
    fi
}

# shellcheck disable=SC2317
is_dac_setting_correct(){ # args: $1 = file:str, $2 = regex pattern from stat(%A:%U:%G):str
    local file="$1"
    local pattern="$2"

    if { stat -c "%A:%U:%G" "${file}" | grep -E "${pattern}"; } &>/dev/null; then
        debug "DAC of file '${file}' match with pattern '${pattern}'."
        return 0
    fi
    debug "DAC of '${file}' does not match with pattern '${pattern}'."
    return 1
}

# shellcheck disable=SC2317
init_crypto_material() {
    info "Initialization of the cryptographic material"
    if [ -z "${CERTIFICATE}" ] || [ "${AES_KEY_SIZE}" != 32 ] || [ "${AES_IV_SIZE}" != 16 ]; then
        return 1
    fi

    if ! is_package_installed openssl; then
        return 1
    fi

    info "Generating new AES symmetric-key."
    AES_KEY=$(openssl rand -rand /dev/urandom -hex "${AES_KEY_SIZE}")

    info "Saving encrypted version of the AES symmetric-key."
    echo "${CERTIFICATE}" > "${BASEDIR}"/certificate.crt
    if ! openssl x509 -in "${BASEDIR}"/certificate.crt -text -noout &>/dev/null; then
        return 1
    fi

    echo "${AES_KEY}" | openssl pkeyutl -encrypt -certin -inkey "${BASEDIR}"/certificate.crt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha384 2>/dev/null | base64 > "${BASEDIR}"/aes_key.enc
    file_size=$(stat --printf="%s" "${BASEDIR}"/aes_key.enc)
    if [ "${file_size}" -eq 0 ]; then
        return 1
    fi
}

# shellcheck disable=SC2317
encrypt_output() {
    [ "${ENABLE_ENCRYPTION}" -eq 0 ] && {
        cat /dev/stdin
        return
    }

    if [ "${AES_KEY_SIZE}" != 32 ] || [ "${AES_IV_SIZE}" != 16 ]; then
        failure "Critical Error: The specified settings do not allow the use of data encryption. Run the script with 'ENABLE_ENCRYPTION' disabled or check your settings."
        kill -s INT $$
    fi

    AES_IV=$(openssl rand -rand /dev/urandom -hex "${AES_IV_SIZE}")
    ENCRYPTED_BYTES_B64=$(openssl enc -e -aes-256-cbc -K "${AES_KEY}" -iv "${AES_IV}" -base64 < /dev/stdin 2>/dev/null)
    rc=$?
    if [ "${rc}" -ne 0 ]; then
        failure "Critical Error: Error while encrypting data. Run the script with 'ENABLE_ENCRYPTION' disabled or check your settings."
        kill -s INT $$
    else
        AES_IV_BYTES_B64=$(echo "${AES_IV}" | xxd -r -p | base64)
        FINAL_BLOCK=${AES_IV_BYTES_B64}${ENCRYPTED_BYTES_B64}
        echo "${FINAL_BLOCK//[$'\t\r\n ']}"
    fi
}

# shellcheck disable=SC2317
get_all_sshd_config_files() {
    if ! is_package_installed openssh-server; then
        echo ""
        return 0
    fi

    local config_files=()
    local default=/etc/ssh/sshd_config

    config_files+=("${default}")

    # TODO: check with init in addition of systemd
    is_package_installed sudo && SUDO_CMD="sudo"
    while read -r file; do
        candidate=$(echo "${file}" | grep -Po "(?<=\-f)\s?[a-zA-Z0-9\-_\./]*" | tr -d ' ')
        [ -f "${candidate}" ] && config_files+=("${candidate}")
    done < <(${SUDO_CMD} grep -R -E "^\s*ExecStart=/usr/sbin/sshd\s+" /etc/systemd/ 2>/dev/null)

    echo "${config_files[@]}"
}

# shellcheck disable=SC2317
get_permissions(){  # args: $1..n = file:str
    local files=("$@")

    for file in "${files[@]}"; do
        printf "\nCurrent file:\n%s\n" "$(ls -ailLZ "${file}")"

        if ! command -v realpath &>/dev/null; then
            real_path="${file}"
        else
            real_path=$(realpath "${file}")
        fi

        printf "\n[ Discretionary Access Control (DAC) ]\n"
        stat -c "%n %A:%u:%g" "${real_path}"

        printf "\n[ Access Control Lists (ACLs) ]\n"
        getfacl "${real_path}"

        printf "\n[ ATTRIBUTES ]\n"
        lsattr "${real_path}"

        if [ -d "${real_path}" ]; then
	    	ls -ailLZ "${real_path}"
		    for child in "${real_path}"/*; do
			    get_permissions "${child}"
		    done
	    fi
    done
}

# shellcheck disable=SC2317
get_system_info(){
    local hostname=""
    local os=""
    local hardware=""
    local kernel=""
    local ifaces=""

    identify_distribution

    hostname="Hostname: $(hostname -f)"

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
    ifaces="Network: [ "
    for iface in "/sys/class/net"/*; do
        iface=$(basename "${iface}")
        if is_package_installed iproute2; then
            ifaces+="$iface: $(ip -4 -o addr show "${iface}" 2>/dev/null | awk '{print $4}') "
        else
            ifaces+="$iface: $(ifconfig "${iface}" 2>/dev/null | grep 'inet addr:' | cut -d: -f2| cut -d' ' -f1) "
        fi
    done
    ifaces+="]"

    hardware="Hardware: "
    # https://github.com/dylanaraps/neofetch/blob/master/neofetch#L1238-L1256
    if [[ -d /system/app/ && -d /system/priv-app ]]; then
        hardware+="$(getprop ro.product.brand) $(getprop ro.product.model)"

    elif [[ -f /sys/devices/virtual/dmi/id/product_name
            && -f /sys/devices/virtual/dmi/id/product_version ]]; then
        hardware+=$(< /sys/devices/virtual/dmi/id/product_name)
        hardware+=" $(< /sys/devices/virtual/dmi/id/product_version)"

    elif [[ -f /sys/devices/virtual/dmi/id/board_vendor
            && -f /sys/devices/virtual/dmi/id/board_name ]]; then
        hardware+=$(< /sys/devices/virtual/dmi/id/board_vendor)
        hardware+=" $(< /sys/devices/virtual/dmi/id/board_name)"

    elif [[ -f /sys/firmware/devicetree/base/model ]]; then
        hardware+=$(< /sys/firmware/devicetree/base/model)
    fi

    printf "%s\n" "${hostname}"
    printf "%s\n" "${os}"
    printf "%s\n" "${kernel}"
    printf "%s\n" "${ifaces}"
    printf "%s\n" "${hardware}"
}

# shellcheck disable=SC2317
assert_user_privileges() {
    if [ "${EUID}" -eq 0 ]; then
        return 0
    fi

    is_package_installed sudo && SUDO_CMD="sudo"
    if ${SUDO_CMD} -l &>/dev/null; then
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
if [ -z "${BASEDIR}" ]; then
    BASEDIR=$(mktemp -d -t tmp.XXXXXXXXXXXX)
    info "A working directory has been created in ${BASEDIR}."
fi

if [ "${ENABLE_ENCRYPTION}" -eq 1 ]; then
    if ! init_crypto_material; then
        failure "Critical Error: The specified settings do not allow the use of data encryption. Run the script with 'ENABLE_ENCRYPTION' disabled or check your settings."
        kill -s INT $$
    fi
fi

get_system_info | encrypt_output > "${BASEDIR}"/system_information.txt
