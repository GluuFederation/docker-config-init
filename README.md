# Config Init

A docker image to generate config required by other docker images used in Gluu Server cluster setup.

## Latest Stable Release

Latest stable release is `gluufederation/config-init:3.0.1_rev1.0.0-beta5`. See `CHANGES.md` for archives.

## Versioning/Tagging

This image uses its own versioning/tagging format.

    <IMAGE-NAME>:<GLUU-SERVER-VERSION>_<INTERNAL-REV-VERSION>

For example, `gluufederation/config-init:3.0.1_rev1.0.0` consists of:

- glufederation/config-init as `<IMAGE_NAME>`; the actual image name
- 3.0.1 as `GLUU-SERVER-VERSION`; the Gluu Server version as setup reference
- rev1.0.0 as `<INTERNAL-REV-VERSION>`; revision made when developing the image

## Installation

Build the image:

```
docker build --rm --force-rm -t gluufederation/config-init:latest .
```

Or get it from Docker Hub:

```
docker pull gluufederation/config-init:latest
```

## Running The Container

To run this container and see available options, type the following command:

```
docker run --rm gluufederation/config-init
```

Here's an example to generate config (and save them to Consul KV):

```
docker run --rm \
    gluufederation/config-init \
    --admin-pw my-password \
    --email 'my-email@my.domain.com' \
    --domain my.domain.com \
    --org-name 'My Organization' \
    --kv-host consul.my.domain.com \
    --kv-port 8500 \
    --country-code US \
    --state TX \
    --city Austin \
    --ldap-type=openldap \
    --save
```

The config and self-signed SSL cert and key will be generated.

To override SSL cert and key:

```
docker run --rm \
    -v /path/to/ssl.cert:/etc/certs/gluu_https.crt \
    -v /path/to/ssl.key:/etc/certs/gluu_https.key \
    gluufederation/config-init \
    --admin-pw my-password \
    --email 'my-email@my.domain.com' \
    --domain my.domain.com \
    --org-name 'My Organization' \
    --kv-host consul.my.domain.com \
    --kv-port 8500 \
    --country-code US \
    --state TX \
    --city Austin \
    --ldap-type=openldap \
    --save
```
