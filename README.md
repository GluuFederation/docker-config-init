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

The output would be:

```
Usage: entrypoint.py [OPTIONS]

Options:
  --admin-pw TEXT           Password for admin access.  [default: admin]
  --email TEXT              Email for support.  [default: support@gluu.example.com]
  --domain TEXT             Domain for Gluu Server.  [default: gluu.example.com]
  --org-name TEXT           Organization name.  [default: Gluu]
  --kv-host TEXT            Hostname/IP address of KV store.  [default: localhost]
  --kv-port INTEGER         Port of KV store.  [default: 8500]
  --save                    Save config to KV store.
  --view                    Show generated config.
  --encoded-salt TEXT       Encoded salt.  [default: ]
  --encoded-ox-ldap-pw TEXT Encoded ox LDAP password. [default: ]
  --inum-appliance TEXT     Inum Appliance.  [default: ]
  --help                    Show this message and exit.
```

Note: all options have their default value.

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
    --save
```

## FAQ

1.  How to connect to remote Consul KV that bind into private IP address?

    By using SSH tunneling, config-init will be able to connect to the KV.
    For example:

    ```
    ssh -L 8500:<PRIVATE-IP-ADDR>:<CONSUL-CLIENT-PORT> <SSH-USER>@<REMOTE-SERVER>
    ```

    Afterwards, pass `--kv-port 8500` option when running the container:

    ```
    docker run --rm \
        -v /path/to/ssl.crt:/etc/certs/gluu_https.crt \
        -v /path/to/ssl.key:/etc/certs/gluu_https.key \
        gluufederation/config-init \
        --admin-pw my-password \
        --email 'my-email@my.domain.com' \
        --domain my.domain.com \
        --org-name 'My Organization' \
        --kv-host consul.my.domain.com \
        --kv-port 8500 \
        --save \
        --view
    ```

2.  How to use existing OpenLDAP (i.e. migrating from CE version of Gluu Server)?

    Here's an example to re-use existing OpenLDAP:

    ```
    docker run --rm \
        -v /path/to/ssl.crt:/etc/certs/gluu_https.crt \
        -v /path/to/ssl.key:/etc/certs/gluu_https.key \
        gluufederation/config-init \
        --admin-pw my-password \
        --email 'my-email@my.domain.com' \
        --domain my.domain.com \
        --org-name 'My Organization' \
        --kv-host consul.my.domain.com \
        --kv-port 8500 \
        --encoded-salt 'pCP8XcmlpaQB4JINpEGi1qyg' \
        --encoded-ox-ldap-pw 'eR3ptEcAgF1=' \
        --inum-appliance '@!F203.2552.5945.B479!0002!9G5B.E07C' \
        --save \
        --view
    ```

    This will generate config for cluster and save them into Consul, but the data in existing OpenLDAP will be left intact.
