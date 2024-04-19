#put your dockerfile contents here
# Taken mostly from other people's Dockerfiles. 
FROM ubuntu:22.04
RUN apt-get update

RUN apt-get update
RUN apt-get install -y xinetd
RUN apt-get install -y python3-pip
RUN /usr/bin/python3 -m pip install pycryptodome
RUN apt-get -y install socat
RUN apt install -y netcat

ENV USER shamir-for-dummies
WORKDIR /home/$USER
RUN useradd $USER

COPY ./src/server.py /home/$USER/server.py
COPY ./deploy/wrapper.sh /home/$USER/wrapper.sh

RUN chown -R root:$USER /home/$USER
RUN chmod -R 550 /home/$USER

EXPOSE 5040

CMD socat TCP-LISTEN:5040,reuseaddr,fork EXEC:"/home/$USER/wrapper.sh"

