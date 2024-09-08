FROM python:3.12-bullseye AS base

RUN apt update ; apt install -y patchelf
RUN pip install pyinstaller staticx

RUN apt-get -y autoremove ; aptitude -y autoclean ; apt-get -y autoclean
RUN rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.aptitude

ADD build /usr/local/bin/build

ENV LANG=es_ES.UTF-8
ENV TERM=xterm-256color

CMD ["/usr/local/bin/build"]
