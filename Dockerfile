FROM openjdk:8-jre-alpine

LABEL maintainer="Gluu Inc. <support@gluu.org>"

# ===============
# Alpine packages
# ===============
RUN apk update && apk add --no-cache \
    openssl \
    py-pip \
    shadow \
    wget

# ====
# Java
# ====

# JAR files required to generate OpenID Connect keys
ENV OX_VERSION 3.1.4.Final
ENV OX_BUILD_DATE 2018-09-27

RUN mkdir -p /opt/config-init/javalibs
RUN wget -q https://ox.gluu.org/maven/org/xdi/oxauth-client/${OX_VERSION}/oxauth-client-${OX_VERSION}-jar-with-dependencies.jar -O /opt/config-init/javalibs/oxauth-client.jar
RUN wget -q https://ox.gluu.org/maven/org/xdi/oxShibbolethKeyGenerator/${OX_VERSION}/oxShibbolethKeyGenerator-${OX_VERSION}.jar -O /opt/config-init/javalibs/idp3_cml_keygenerator.jar

# ====
# Tini
# ====

ENV TINI_VERSION v0.18.0
RUN wget -q https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static -O /usr/bin/tini \
&& chmod +x /usr/bin/tini

# ======
# Python
# ======

WORKDIR /opt/config-init
COPY requirements.txt ./
RUN pip install --no-cache-dir -U pip \
    && pip install --no-cache-dir -r requirements.txt

ENV GLUU_CONFIG_ADAPTER consul
ENV GLUU_CONSUL_HOST localhost
ENV GLUU_CONSUL_PORT 8500
# force to use default consistency mode
ENV GLUU_CONSUL_CONSISTENCY default
ENV GLUU_CONSUL_SCHEME http
ENV GLUU_CONSUL_VERIFY false
ENV GLUU_CONSUL_CACERT_FILE /etc/certs/consul_ca.crt
ENV GLUU_CONSUL_CERT_FILE /etc/certs/consul_client.crt
ENV GLUU_CONSUL_KEY_FILE /etc/certs/consul_client.key
ENV GLUU_CONSUL_TOKEN_FILE /etc/certs/consul_token
ENV GLUU_KUBERNETES_NAMESPACE default
ENV GLUU_KUBERNETES_CONFIGMAP gluu

# ====
# misc
# ====

COPY scripts /opt/config-init/scripts
COPY templates /opt/config-init/templates
COPY static /opt/config-init/static

RUN mkdir -p /etc/certs /opt/config-init/db
RUN chmod +x /opt/config-init/scripts/entrypoint.sh

# create gluu user
RUN useradd -ms /bin/sh --uid 1000 gluu \
    && usermod -a -G root gluu

# adjust ownership
RUN chown -R 1000:1000 /opt/config-init \
    && chgrp -R 0 /opt/config-init && chmod -R g=u /opt/config-init \
    && chgrp -R 0 /etc/certs && chmod -R g=u /etc/certs

# run the entrypoint as gluu user
USER 1000

ENTRYPOINT ["tini", "-g", "--", "/opt/config-init/scripts/entrypoint.sh"]
CMD ["--help"]
