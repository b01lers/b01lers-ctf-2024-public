# We can build from whatever version
# we want. 20.04 is most typical now.

FROM ubuntu:latest

RUN apt-get update && apt-get install python3-pip -y
RUN apt-get update && apt-get install sudo -y


ENV USER PwnHub
WORKDIR /home/$USER
RUN useradd $USER


ADD static /home/$USER/static
ADD templates /home/$USER/templates
COPY ./requirements.txt /home/$USER/
COPY ./app.py /home/$USER/

RUN pip3 install -r requirements.txt

# We don't want to forget the flag!
COPY ./flag.txt /flag.txt


RUN chown -R root:$USER /home/$USER
RUN chmod -R 550 /home/$USER
RUN chmod -x /flag.txt

EXPOSE 5000

CMD ["sudo","-u","PwnHub","python3", "-m" , "flask", "run", "--host=0.0.0.0"]
