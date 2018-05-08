FROM openjdk:jre-alpine

LABEL maintainer="Gluu Inc. <support@gluu.org>"

# ===============
# Alpine packages
# ===============
RUN apk update && apk add --no-cache \
    py-pip \
    openssl

# JAR files required to generate OpenID Connect keys
ENV OX_VERSION 3.1.3.Final
ENV OX_BUILD_DATE 2018-04-30
RUN mkdir -p /opt/config-init/javalibs \
    && wget -q http://ox.gluu.org/maven/org/xdi/oxauth-client/${OX_VERSION}/oxauth-client-${OX_VERSION}-jar-with-dependencies.jar -O /opt/config-init/javalibs/keygen.jar

# ======
# Python
# ======

RUN pip install -U pip
WORKDIR /opt/config-init
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# ====
# misc
# ====
COPY entrypoint.py ./
COPY templates ./templates
COPY static ./static

RUN mkdir -p /etc/certs /opt/config-init/db

ENTRYPOINT ["python", "./entrypoint.py"]
CMD ["--help"]
