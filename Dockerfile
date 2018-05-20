FROM python:2.7-alpine

RUN apk add --update build-base
RUN apk add --update libffi-dev libxml2-dev libxslt-dev openssl openssl-dev

RUN pip install -U pip
RUN pip install https://github.com/datacenter/pyaci/archive/master.zip

COPY meta/aci-meta.limited.json /root/.aci-meta/aci-meta.limited.json
RUN cd /root/.aci-meta && ln -s aci-meta.limited.json aci-meta.json
