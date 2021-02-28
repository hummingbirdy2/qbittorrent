#!/bin/bash

# Generation of the Wireguard config file for PIA VPN
#
# Sourced form: https://github.com/pia-foss/manual-connections
# Inspired by the work of binhex: https://github.com/binhex/arch-qbittorrentvpn
#
# Licence requirement:
# --------------------------------------
# Copyright (C) 2020 Private Internet Access, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# --------------------------------------
# 
# Dependencies:
# --------------------------------------
# - curl
# - jq
# --------------------------------------

# Constant
WAIT_TOKEN=10


echo "[INFO] Start of the PIA VPN configuration script"

# Confirm format of VPN_USER for PIA VPN
echo "[INFO] Confirm format of PIA username into VPN_USER..."
unPrefix=$( echo ${VPN_USER:0:1} )
unSuffix=$( echo ${VPN_USER:1} )
if [[ -z "$VPN_USER" ]]; then
    echo "[ERROR] You must provide a PIA username into VPN_USER."
    exit 1
elif [[ ${#VPN_USER} != 8 ]]; then
    echo "[ERROR] A PIA username is always 8 characters long."
    exit 1
elif [[ $unPrefix != "P" ]] && [[ $unPrefix != "p" ]]; then
    echo "[ERROR] A PIA username must start with \"p\"."
    exit 1
elif ! [[ $unSuffix =~ $intCheck ]]; then
    echo "[ERROR] Username formatting is always p#######!"
    exit 1
else
    echo "[INFO] VPN_USER=$VPN_USER"
fi

# Confirm format of VPN_PASS for PIA VPN
echo "[INFO] Confirm format of PIA password into VPN_PASS..."
if [[ -z "$VPN_PASS" ]]; then
    echo "[ERROR] You must provide a PIA password into VPN_PASS."
    exit 1
elif [[ ${#VPN_PASS} -lt 8 ]]; then
    echo "[ERROR] A PIA password is always a minimum of 8 characters long."
    exit 1
else
    echo "[INFO] VPN_PASS=**********"
fi

# Checking login credentials
echo "[INFO] Generate token..."
	while true; do

		# jq (json query tool) query to select current vpn remote server (from env var) and then get metadata server ip address
		jq_query_metadata_ip=".regions | .[] | select(.dns | match(\"^${VPN_REMOTE_SERVER}\")) | .servers | .meta | .[] | .ip"

		# get metadata server ip address
		vpn_remote_metadata_server_ip=$(echo "${PIA_VPNINFO_API}" | jq -r "${jq_query_metadata_ip}")

		# get token json response BEFORE vpn established
		token_json_response=$(curl --silent --insecure -u "${VPN_USER}:${VPN_PASS}" "https://${vpn_remote_metadata_server_ip}/authv3/generateToken")

		if [ "$(echo "${token_json_response}" | jq -r '.status')" != "OK" ]; then

			echo "[warn] Unable to successfully download PIA json to generate token from URL 'https://${vpn_remote_metadata_server_ip}/authv3/generateToken'"
			echo "[info] Retrying in ${retry_wait_secs} secs..."
			sleep "${retry_wait_secs}"s

		else

			break

		fi

	done









generateTokenResponse=$(curl -s -u "$VPN_USER:$VPN_PASS" \
  "https://privateinternetaccess.com/gtoken/generateToken")

if [ "$(echo "$generateTokenResponse" | jq -r '.status')" != "OK" ]; then
  echo "[ERROR] Could not authenticate with the login credentials provided!"
  exit 1
fi

echo "[INFO] OK !"


# Generate token
echo "[INFO] Generate PIA token"
token=$(echo "$generateTokenResponse" | jq -r '.token')
tokenExpiration=$(date +"%c" --date='1 day')