FROM openjdk:8-jre-alpine

LABEL maintainer="Gluu Inc. <support@gluu.org>"

# ===============
# Alpine packages
# ===============
RUN apk update && apk add --no-cache \
    openssl \
    py-pip \
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

# ======
# Python
# ======

WORKDIR /opt/config-init
COPY requirements.txt ./
RUN pip install --no-cache-dir -U pip \
    && pip install --no-cache-dir -r requirements.txt

# =======
# License
# =======

RUN mkdir -p /licenses
COPY LICENSE /licenses/

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
ENV GLUU_AUTO_ACK_LICENSE false

# ====
# misc
# ====
COPY scripts ./scripts
COPY templates ./templates
COPY static ./static

RUN mkdir -p /etc/certs /opt/config-init/db
RUN chmod +x ./scripts/license_checker.py

ENTRYPOINT ["/opt/config-init/scripts/license_checker.py", "python", "/opt/config-init/scripts/entrypoint.py"]
CMD ["--help"]
