# By default - docker build will pull master
# If you want the local WS to be used - please use
# "--build-arg ." to the docker build command - like:
#
# 'docker build -t mypyaci:latest --build-arg PYACI_SOURCE=. .
# You can only specify '.' as PYACI_SOURCE
#

FROM python:2.7-alpine
ARG PYACI_SOURCE=https://github.com/datacenter/pyaci/archive/master.zip

RUN apk add --update build-base
RUN apk add --update libffi-dev libxml2-dev libxslt-dev openssl openssl-dev

WORKDIR /localws

#hadolint ignore=DL3013
RUN pip install -U pip
COPY . $WORKDIR
#hadolint ignore=DL3013
RUN pip install $PYACI_SOURCE

COPY meta/aci-meta.limited.json /root/.aci-meta/aci-meta.limited.json
RUN cd /root/.aci-meta && ln -s aci-meta.limited.json aci-meta.json
