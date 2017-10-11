FROM ubuntu:14.04

MAINTAINER Gluu Inc. <support@gluu.org>

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y --force-yes \
    python \
    python-dev \
    python-pip \
    swig \
    libssl-dev \
    openjdk-7-jre-headless \
    wget \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# JAR files required to generate OpenID Connect keys
ENV OX_VERSION 3.1.1.Final
ENV OX_BUILD_DATE 2017-10-11
RUN mkdir -p /opt/config-init/javalibs
RUN wget -q http://ox.gluu.org/maven/org/xdi/oxauth-client/${OX_VERSION}/oxauth-client-${OX_VERSION}-jar-with-dependencies.jar -O /opt/config-init/javalibs/keygen.jar

RUN pip install -U pip

# A workaround to address https://github.com/docker/docker-py/issues/1054
# and to make sure latest pip is being used, not from OS one
ENV PYTHONPATH="/usr/local/lib/python2.7/dist-packages:/usr/lib/python2.7/dist-packages"

WORKDIR /opt/config-init

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY entrypoint.py ./
COPY templates ./templates
COPY static ./static

RUN mkdir -p /etc/certs

ENTRYPOINT ["python", "./entrypoint.py"]
CMD ["--help"]
