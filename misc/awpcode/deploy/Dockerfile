FROM python:3.11.6

RUN apt-get update && apt-get install -y socat
RUN apt-get update && apt-get install -y sudo

ENV USER awpcode
WORKDIR /home/$USER
RUN useradd $USER

COPY ./deploy/wrapper.sh /home/$USER/

COPY ./src/chal.py /home/$USER/

COPY ./flag.txt /flag.txt

RUN chown -R root:$USER /home/$USER
RUN chmod -R 550 /home/$USER
RUN chmod -x /flag.txt

EXPOSE 1337

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"/home/$USER/wrapper.sh"