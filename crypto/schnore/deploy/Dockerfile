#put your dockerfile contents here
FROM ubuntu:20.04

RUN apt-get update #&& apt-get -y upgrade
#RUN apt install software-properties-common -y

#RUN add-apt-repository ppa:deadsnakes/ppa -y
RUN apt-get install -y socat
RUN apt-get install -y sudo

ENV USER schnore
WORKDIR /home/$USER
RUN useradd $USER

RUN apt-get install -y python3.8
RUN apt-get install -y python3-pip
RUN python3.8 -m pip install PyCryptodome

COPY ./deploy/wrapper.sh /home/$USER/
COPY ./flag.txt /home/$USER/flag.txt
COPY ./dist/chal.py /home/$USER/chal.py

RUN chown -R root:$USER /home/$USER
RUN chmod -R 550 /home/$USER
RUN chmod -x /home/$USER/flag.txt

EXPOSE 1337

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"/home/$USER/wrapper.sh"
