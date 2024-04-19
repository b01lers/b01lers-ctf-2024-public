FROM tiangolo/uvicorn-gunicorn-starlette:python3.11

RUN apt-get update && apt-get -y upgrade
RUN pip install --upgrade pip
COPY requirements.txt /
RUN pip install -r /requirements.txt && rm /requirements.txt

COPY ./app /app

RUN groupadd -r ctf && useradd -M -r -g ctf ctf
RUN mkdir /app/uploads
ENV LISTEN_PORT=80
EXPOSE 80
VOLUME /tmp /var/ /run