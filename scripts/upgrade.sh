#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/crowdsec-cloud-bouncer"
BIN_PATH="./crowdsec-cloud-bouncer"


upgrade_bin() {
    rm "${BIN_PATH_INSTALLED}" || (echo "crowdsec-cloud-bouncer is not installed, exiting." && exit 1)
    install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
}


if ! [ $(id -u) = 0 ]; then
    log_err "Please run the upgrade script as root or with sudo"
    exit 1
fi

systemctl stop crowdsec-cloud-bouncer
upgrade_bin
systemctl start crowdsec-cloud-bouncer
echo "crowdsec-cloud-bouncer upgraded successfully."
