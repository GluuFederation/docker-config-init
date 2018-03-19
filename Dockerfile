FROM openjdk:jre-alpine

LABEL maintainer="Gluu Inc. <support@gluu.org>"

# ===============
# Alpine packages
# ===============
RUN apk update && apk add --no-cache \
    py-pip \
    openssl \
    openssl-dev \
    gcc \
    musl-dev \
    python-dev \
    swig

# JAR files required to generate OpenID Connect keys
ENV OX_VERSION 3.1.2.Final
ENV OX_BUILD_DATE 2018-01-18
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

RUN mkdir -p /etc/certs

ENTRYPOINT ["python", "./entrypoint.py"]
CMD ["--help"]
