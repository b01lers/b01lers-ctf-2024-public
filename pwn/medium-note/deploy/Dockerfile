<<<<<<< Updated upstream
#put your dockerfile contents here

FROM ubuntu:latest
=======
FROM ubuntu@sha256:50ec5c3a1814f5ef82a564fae94f6b4c5d550bb71614ba6cfe8fadbd8ada9f12
>>>>>>> Stashed changes

RUN apt-get update && apt-get install socat gcc patchelf sudo -y
ENV USER medium-note
WORKDIR ../


COPY ./src/chal.c /chal.c

COPY ./dist/ld-2.36.so /ld-2.36.so


COPY ./dist/libc-2.36.so.6 /glibc/2.36/64/lib/libc.so.6
COPY ./dist/chal /chal
COPY ./flag.txt ./flag.txt


RUN chmod +x /chal
RUN patchelf --set-rpath . /chal

EXPOSE 4401

<<<<<<< Updated upstream
CMD socat TCP-LISTEN:4401,reuseaddr,fork EXEC:"/ld-2.36.so /chal"

=======
CMD socat TCP-LISTEN:4401,reuseaddr,fork EXEC:"/tmp/ld-2.36.so /chal"
>>>>>>> Stashed changes
