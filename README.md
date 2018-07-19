# Config Init

A docker image to generate the necessary configuration required by other docker Gluu Server images.

## Versioning/Tagging

This image uses its own versioning/tagging format.

    <IMAGE-NAME>:<GLUU-SERVER-VERSION>_<RELEASE_VERSION>

For example, `gluufederation/config-init:3.1.3_02` consists of:

- `glufederation/config-init` as `<IMAGE_NAME>`; the actual image name
- `3.1.3` as `GLUU-SERVER-VERSION`; the Gluu Server version as setup reference
- `02` as `<RELEASE_VERSION>`

## Installation

    docker pull gluufederation/config-init:3.1.3_02

## Environment Variables

- `GLUU_CONFIG_ADAPTER`: config backend (either `consul` for Consul KV or `kubernetes` for Kubernetes configmap)

The following environment variables are activated only if `GLUU_CONFIG_ADAPTER` is set to `consul`:

- `GLUU_CONSUL_HOST`: hostname or IP of Consul (default to `localhost`)
- `GLUU_CONSUL_PORT`: port of Consul (default to `8500`)
- `GLUU_CONSUL_CONSISTENCY`: Consul consistency mode (choose one of `default`, `consistent`, or `stale`). Default to `stale` mode.

otherwise, if `GLUU_CONFIG_ADAPTER` is set to `kubernetes`:

- `GLUU_KUBERNETES_NAMESPACE`: Kubernetes namespace (default to `default`)
- `GLUU_KUBERNETES_CONFIGMAP`: Kubernetes configmap name (default to `gluu`)

## Running The Container

To run this container and see available options, type the following command:

    docker run --rm gluufederation/config-init:3.1.3_02 --help

### Generate Command

Here's an example to generate config, save them to config backend (Consul KV or Kubernetes configmap) and JSON file:

```
docker run --rm \
    -e GLUU_CONFIG_ADAPTER=consul \
    -e GLUU_CONSUL_HOST=consul.example.com \
    gluufederation/config-init:3.1.3_02 generate \
    --admin-pw secret \
    --email 'support@example.com' \
    --domain example.com \
    --org-name 'My Organization' \
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
    -v /path/to/config/db:/opt/config-init/db \
    -e GLUU_CONFIG_ADAPTER=consul \
    -e GLUU_CONSUL_HOST=consul.example.com \
    gluufederation/config-init:3.1.3_02 generate \
    --admin-pw secret \
    --email 'support@example.com' \
    --domain example.com \
    --org-name 'My Organization' \
    --country-code US \
    --state TX \
    --city Austin \
    --ldap-type=opendj \
    --path /opt/config-init/db/config.json
```

### Dump Command

Dump configuration configuration into a JSON file.

Example on how to dump into host's `$HOME/db/config.json` file:

```
docker run --rm \
    -v $HOME/db:/opt/config-init/db \
    -e GLUU_CONFIG_ADAPTER=consul \
    -e GLUU_CONSUL_HOST=consul.example.com \
    gluufederation/config-init:3.1.3_02 dump \
    --path /opt/config-init/db/config.json
```

### Load Command

Load configuration from a JSON file.

Example on how to load from host's `$HOME/db/config.json` file:

```
docker run --rm \
    -v $HOME/db:/opt/config-init/db \
    -e GLUU_CONFIG_ADAPTER=consul \
    -e GLUU_CONSUL_HOST=consul.example.com \
    gluufederation/config-init:3.1.3_02 load \
    --path /opt/config-init/db/config.json
```
