FROM openjdk:8-jre-alpine3.9

LABEL maintainer="Gluu Inc. <support@gluu.org>"

# ===============
# Alpine packages
# ===============

RUN apk update && apk add --no-cache \
    openssl \
    py-pip \
    shadow \
    wget \
    git

# ====
# Java
# ====

# JAR files required to generate OpenID Connect keys
ENV OX_VERSION=4.0.b1 \
    OXAUTH_CLIENT_BUILD_DATE=2019-07-23 \
    OXSHIBBOLETH_KEYGEN_BUILD_DATE=2019-07-23

RUN mkdir -p /opt/config-init/javalibs \
    && wget -q https://ox.gluu.org/maven/org/gluu/oxauth-client/${OX_VERSION}/oxauth-client-${OX_VERSION}-jar-with-dependencies.jar -O /opt/config-init/javalibs/oxauth-client.jar

# RUN wget -q https://ox.gluu.org/maven/org/gluu/oxShibbolethKeyGenerator/${OX_VERSION}/oxShibbolethKeyGenerator-${OX_VERSION}.jar -O /opt/config-init/javalibs/idp3_cml_keygenerator.jar

# ====
# Tini
# ====

RUN wget -q https://github.com/krallin/tini/releases/download/v0.18.0/tini-static -O /usr/bin/tini \
    && chmod +x /usr/bin/tini

# ======
# Python
# ======

COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -U pip \
    && pip install --no-cache-dir -r /tmp/requirements.txt \
    && apk del git

# =======
# License
# =======

RUN mkdir -p /licenses
COPY LICENSE /licenses/

# ==========
# Config ENV
# ==========

ENV GLUU_CONFIG_ADAPTER=consul \
    GLUU_CONFIG_CONSUL_HOST=localhost \
    GLUU_CONFIG_CONSUL_PORT=8500 \
    GLUU_CONFIG_CONSUL_CONSISTENCY=default \
    GLUU_CONFIG_CONSUL_SCHEME=http \
    GLUU_CONFIG_CONSUL_VERIFY=false \
    GLUU_CONFIG_CONSUL_CACERT_FILE=/etc/certs/consul_ca.crt \
    GLUU_CONFIG_CONSUL_CERT_FILE=/etc/certs/consul_client.crt \
    GLUU_CONFIG_CONSUL_KEY_FILE=/etc/certs/consul_client.key \
    GLUU_CONFIG_CONSUL_TOKEN_FILE=/etc/certs/consul_token \
    GLUU_CONFIG_KUBERNETES_NAMESPACE=default \
    GLUU_CONFIG_KUBERNETES_CONFIGMAP=gluu \
    GLUU_CONFIG_KUBERNETES_USE_KUBE_CONFIG=false

# ==========
# Secret ENV
# ==========

ENV GLUU_SECRET_ADAPTER=vault \
    GLUU_SECRET_VAULT_SCHEME=http \
    GLUU_SECRET_VAULT_HOST=localhost \
    GLUU_SECRET_VAULT_PORT=8200 \
    GLUU_SECRET_VAULT_VERIFY=false \
    GLUU_SECRET_VAULT_ROLE_ID_FILE=/etc/certs/vault_role_id \
    GLUU_SECRET_VAULT_SECRET_ID_FILE=/etc/certs/vault_secret_id \
    GLUU_SECRET_VAULT_CERT_FILE=/etc/certs/vault_client.crt \
    GLUU_SECRET_VAULT_KEY_FILE=/etc/certs/vault_client.key \
    GLUU_SECRET_VAULT_CACERT_FILE=/etc/certs/vault_ca.crt \
    GLUU_SECRET_KUBERNETES_NAMESPACE=default \
    GLUU_SECRET_KUBERNETES_SECRET=gluu \
    GLUU_SECRET_KUBERNETES_USE_KUBE_CONFIG=false

# ===========
# Generic ENV
# ===========

ENV GLUU_OVERWRITE_ALL=false \
    GLUU_WAIT_MAX_TIME=300 \
    GLUU_WAIT_SLEEP_DURATION=5

# ====
# misc
# ====

COPY scripts /opt/config-init/scripts
COPY templates /opt/config-init/templates
COPY static /opt/config-init/static

RUN mkdir -p /etc/certs /opt/config-init/db

# # create gluu user
# RUN useradd -ms /bin/sh --uid 1000 gluu \
#     && usermod -a -G root gluu

# # adjust ownership
# RUN chown -R 1000:1000 /opt/config-init \
#     && chgrp -R 0 /opt/config-init && chmod -R g=u /opt/config-init \
#     && chgrp -R 0 /etc/certs && chmod -R g=u /etc/certs

# # run the entrypoint as gluu user
# USER 1000

ENTRYPOINT ["tini", "-g", "--", "sh", "/opt/config-init/scripts/entrypoint.sh"]
CMD ["--help"]
