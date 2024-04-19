#put your dockerfile contents here
# We can build from whatever version
# we want. 22.04 is most typical now(?)

FROM ubuntu:22.04
#FROM python:3

# Install any software needed to
# build the challenge

RUN apt-get update
RUN apt-get install -y xinetd


RUN apt-get install -y python3-pip
RUN /usr/bin/python3 -m pip install pycryptodome
# Change example to the name of your challenge.

ENV USER count_the_counter
WORKDIR /home/$USER
RUN useradd $USER

# This adds the critical files.

#COPY ./deploy/requirements.txt .
#RUN pip3 install -r requirements.txt

# wrapper.sh wraps the executable by
# `cd`ing to the right place

COPY ./deploy/wrapper.sh ./

# The xinetd configuration provides run options
# but is very boilerplate. See below.
COPY ./deploy/$USER.xinetd /etc/xinetd.d/$USER

COPY ./src/chal.py ./
COPY ./src/secret.py ./

# We don't want to forget the flag! -> already in ./src
#COPY ./solve/flag.txt /home/$USER/flag.txt

# Set permissions. Be *VERY* careful
# about changing this!
RUN chown -R root:$USER /home/$USER
RUN chmod -R 550 /home/$USER
RUN chmod -x /home/$USER/secret.py
RUN chmod -x /home/$USER/chal.py
RUN touch /var/log/xinetdlog

# Whatever port you configured in xinetd.
# PROBABLY this should stay 1337. Just change
# The passthrough port in docker-compose.yml below.
EXPOSE 2001

# Start the container by starting xinetd and outputting
# the xinetd log for debugging.
ENTRYPOINT service xinetd start && sleep 2 && tail -f /var/log/xinetdlog
