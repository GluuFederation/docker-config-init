# Config Init

A docker image to generate the necessary configuration required by other docker Gluu Server images.

## Versioning/Tagging

This image uses its own versioning/tagging format.

    <IMAGE-NAME>:<GLUU-SERVER-VERSION>_<RELEASE_VERSION>

For example, `gluufederation/config-init:3.1.3_01` consists of:

- `glufederation/config-init` as `<IMAGE_NAME>`; the actual image name
- `3.1.3` as `GLUU-SERVER-VERSION`; the Gluu Server version as setup reference
- `01` as `<RELEASE_VERSION>`

## Installation

    docker pull gluufederation/config-init:3.1.3_01

## Running The Container

To run this container and see available options, type the following command:

    docker run --rm gluufederation/config-init:3.1.3_01 --help

### Generate Command

Here's an example to generate config (and save them to Consul KV):

```
docker run --rm \
    gluufederation/config-init:3.1.3_01 generate \
    --admin-pw secret \
    --email 'support@example.com' \
    --domain example.com \
    --org-name 'My Organization' \
    --kv-host consul.example.com \
    --kv-port 8500 \
    --country-code US \
    --state TX \
    --city Austin \
    --ldap-type=opendj
```

The config and self-signed SSL certs and keys will be generated.

To override SSL cert and key for HTTPS:

```
docker run --rm \
    -v /path/to/ssl.cert:/etc/certs/gluu_https.crt \
    -v /path/to/ssl.key:/etc/certs/gluu_https.key \
    gluufederation/config-init:3.1.3_01 generate \
    --admin-pw secret \
    --email 'support@example.com' \
    --domain example.com \
    --org-name 'My Organization' \
    --kv-host consul.example.com \
    --kv-port 8500 \
    --country-code US \
    --state TX \
    --city Austin \
    --ldap-type=opendj
```

### Dump Command

Dump configuration configuration into a JSON file.

Example on how to dump into host's `$HOME/db/config.json` file:

```
docker run --rm \
    -v $HOME/db:/opt/config-init/db \
    gluufederation/config-init:3.1.3_01 dump \
    --kv-host consul.example.com \
    --kv-port 8500 \
    --path /opt/config-init/db/config.json
```

### Load Command

Load configuration from a JSON file.

Example on how to load from host's `$HOME/db/config.json` file:

```
docker run --rm \
    -v $HOME/db:/opt/config-init/db \
    gluufederation/config-init:3.1.3_01 load \
    --kv-host consul.example.com \
    --kv-port 8500 \
    --path /opt/config-init/db/config.json
```
