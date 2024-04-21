FROM pwn.red/jail

COPY --from=ubuntu@sha256:69ce9399fe60c5710baee8416b7991183653c3d577afc2b0e3bfe508d7c76142 / /srv
COPY dist/b01lers_bracket /srv/app/run
COPY flag.txt /srv/app/flag.txt
RUN chmod 755 /srv/app/run

ENV JAIL_MEM=10M JAIL_TIME=120
