#put your dockerfile contents here

# Taken mostly from other people's Dockerfiles. 
FROM ubuntu:22.04
RUN apt-get update -y
RUN apt-get update --fix-missing -y
RUN apt-get install -y libzbar0

ENV USER texnically
WORKDIR /home/$USER
RUN useradd $USER

RUN apt-get -y install socat
# RUN apt-get -y install xinetd
# RUN apt-get -y install python3
RUN apt-get -y install python3-pip
RUN apt-get -y install --no-install-recommends pandoc texlive
RUN apt install -y netcat
RUN pip install colorama
RUN apt-get -y install libpoppler-cpp-dev
RUN apt-get -y install poppler-utils fonts-ipaexfont-gothic

COPY ./deploy/wrapper.sh /home/$USER/
COPY ./src/server.py /home/$USER/server.py
COPY ./src/lipsum.sty /home/$USER/lipsum.sty

COPY ./deploy/wrapper.sh ./

# Set permissions. Be *VERY* careful
# about changing this!
RUN chown -R root:$USER /home/$USER
RUN chmod -R 550 /home/$USER

EXPOSE 4001

CMD ["bash", "-c", "PYTHONUNBUFFERED=1 socat TCP-LISTEN:4001,reuseaddr,fork EXEC:\"/home/$USER/wrapper.sh\""]
# ENTRYPOINT service xinetd start && sleep 2 && tail -f /var/log/xinetdlog
