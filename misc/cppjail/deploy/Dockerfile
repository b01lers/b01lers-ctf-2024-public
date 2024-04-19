#put your dockerfile contents here
FROM python:3.11.6

RUN apt-get update && apt-get install -y socat
RUN apt-get update && apt-get install -y sudo

ENV USER cppjail
WORKDIR /home/$USER
RUN useradd $USER

COPY ./src/compile.py /home/$USER/
COPY ./src/cppjail.cpp /home/$USER/
COPY ./src/flag.h /home/$USER/

RUN chown -R root:$USER /home/$USER
RUN chmod -R 550 /home/$USER

EXPOSE 1337

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"/home/$USER/compile.py"