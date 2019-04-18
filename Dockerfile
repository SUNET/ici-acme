FROM debian:testing

MAINTAINER eduid-dev <eduid-dev@SEGATE.SUNET.SE>

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -y update && apt-get -y install \
    git \
    python3-pip \
    python3.7-venv

COPY . /ici_acme/src
RUN (cd /ici_acme/src; git describe; git log -n 1) > /revision.txt
RUN rm -rf /src/.git
RUN python3.7 -m venv /ici_acme/env
RUN /ici_acme/env/bin/pip install -U pip wheel
RUN /ici_acme/env/bin/pip install -r /ici_acme/src/requirements.txt

VOLUME [ "/var/lib/ici_acme" ]

EXPOSE "8000"

WORKDIR "/ici_acme/src"
ENV GUNICORN_CMD_ARGS="--bind=0.0.0.0:8000"
CMD [ "/ici_acme/env/bin/gunicorn", "ici_acme.app:api" ]
