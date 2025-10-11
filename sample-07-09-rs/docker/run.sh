#!/usr/bin/env bash
DEFAULT_LOG_LEVEL="info"

CONFIG_STRING="--asset-dir=/webauthn/assets "

if [ -n "${LISTEN_ADDRESS}" ]; then
  CONFIG_STRING="${CONFIG_STRING} --listen-address=${LISTEN_ADDRESS}"
fi

if [ -n "${RP_ID}" ]; then
  CONFIG_STRING="${CONFIG_STRING} --rp-id=${RP_ID}"
fi

if [ -n "${RP_ORIGIN}" ]; then
  CONFIG_STRING="${CONFIG_STRING} --rp-origin=${RP_ORIGIN}"
fi

if [ -n "${RP_NAME}" ]; then
  CONFIG_STRING="${CONFIG_STRING} --rp-name=${RP_NAME}"
fi

if [ -n "${COOKIE_NAME}" ]; then
  CONFIG_STRING="${CONFIG_STRING} --cookie-name=${COOKIE_NAME}"
fi


##########################
# start
echo "Start with logg level ${LOG_LEVEL:-${DEFAULT_LOG_LEVEL}}"
RUST_LOG=${LOG_LEVEL:-${DEFAULT_LOG_LEVEL}} /webauthn/bin/webauthn_sample ${CONFIG_STRING}
