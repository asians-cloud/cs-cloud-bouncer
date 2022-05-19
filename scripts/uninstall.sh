#!/usr/bin/env bash

SYSTEMD_PATH_FILE="/etc/systemd/system/crowdsec-cloud-bouncer.service"
LOG_FILE="/var/log/crowdsec-cloud-bouncer.log"
CONFIG_DIR="/etc/crowdsec/bouncers"
BIN_PATH_INSTALLED="/usr/local/bin/crowdsec-cloud-bouncer"

uninstall() {
	systemctl stop crowdsec-cloud-bouncer
	rm -f "${CONFIG_DIR}/crowdsec-cloud-bouncer.yaml"
	rm -f "${SYSTEMD_PATH_FILE}"
	rm -f "${BIN_PATH_INSTALLED}"
	rm -f "${LOG_FILE}"
}

uninstall

echo "crowdsec-cloud-bouncer uninstall successfully"
