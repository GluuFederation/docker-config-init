#!/bin/sh

set -e

if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && python /opt/config-init/scripts/entrypoint.py "$@"
else
    python /opt/config-init/scripts/entrypoint.py "$@"
fi
