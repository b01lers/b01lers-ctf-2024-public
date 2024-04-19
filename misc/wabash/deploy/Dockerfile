FROM python:slim AS app

RUN pip install --no-cache-dir progress

FROM pwn.red/jail

COPY --from=app / /srv

COPY ./src/wabash.py /srv/app/run
COPY flag.txt /srv/flag.txt
RUN chmod 775 /srv/app/run


ENV JAIL_TIME=120 JAIL_MEM=10M JAIL_PORT=1337