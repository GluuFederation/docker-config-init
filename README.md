# Config Init

A docker image to generate config required by other docker images used in Gluu Server cluster setup.

## Versioning/Tagging

This image uses its own versioning/tagging format.

    <IMAGE-NAME>:<GLUU-SERVER-VERSION>_<INTERNAL-REV-VERSION>

For example, `gluufederation/config-init:3.1.2_r1` consists of:

- glufederation/config-init as `<IMAGE_NAME>`; the actual image name
- 3.2.2 as `GLUU-SERVER-VERSION`; the Gluu Server version as setup reference
- r1 `<INTERNAL-REV-VERSION>`; revision made when developing the image

## Installation

```
docker pull gluufederation/config-init:3.1.2_dev
```

## Running The Container

To run this container and see available options, type the following command:

```
docker run --rm gluufederation/config-init:3.1.2_dev --help
```

### Generate Command

Here's an example to generate config (and save them to Consul KV):

```
docker run --rm \
    gluufederation/config-init:3.1.2_dev generate \
    --admin-pw my-password \
    --email 'my-email@my.domain.com' \
    --domain my.domain.com \
    --org-name 'My Organization' \
    --kv-host consul.my.domain.com \
    --kv-port 8500 \
    --country-code US \
    --state TX \
    --city Austin \
    --ldap-type=openldap
```

The config and self-signed SSL cert and key will be generated.

To override SSL cert and key:

```
docker run --rm \
    -v /path/to/ssl.cert:/etc/certs/gluu_https.crt \
    -v /path/to/ssl.key:/etc/certs/gluu_https.key \
    gluufederation/config-init:3.1.2_dev generate \
    --admin-pw my-password \
    --email 'my-email@my.domain.com' \
    --domain my.domain.com \
    --org-name 'My Organization' \
    --kv-host consul.my.domain.com \
    --kv-port 8500 \
    --country-code US \
    --state TX \
    --city Austin \
    --ldap-type=openldap
```

### Dump Command

Dump configuration configuration into a JSON file.

```
docker run --rm \
    -v $HOME/db:/opt/config-init/db \
    gluufederation/config-init:3.1.2_dev dump \
    --kv-host consul.my.domain.com \
    --kv-port 8500 \
    --path /opt/config-init/db/config.json
```

### Load Command

Load configuration from a JSON file.

```
docker run --rm \
    -v $HOME/db/config.json:/opt/config-init/db/config.json \
    gluufederation/config-init:3.1.2_dev load \
    --kv-host consul.my.domain.com \
    --kv-port 8500 \
    --path /opt/config-init/db/config.json
```
