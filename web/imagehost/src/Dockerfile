FROM tiangolo/uvicorn-gunicorn-starlette:python3.11

RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y mariadb-server mariadb-client libmariadb-dev openssl libjpeg62-turbo zlib1g libwebp7

RUN pip install --upgrade pip
COPY requirements.txt /
RUN pip install -r /requirements.txt && rm /requirements.txt

COPY ./app /app
COPY ../flag.png /flag.png

RUN groupadd -r ctf && useradd -M -r -g ctf ctf

RUN chmod 700 /app/run.sh
CMD ["/app/run.sh"]

RUN mkdir -p /run/mysqld && chown -R mysql:mysql /run/mysqld && \
	mkdir -p /uploads && chown root:ctf /uploads && \
	openssl genrsa -out /app/private_key.pem 4096 && openssl rsa -in /app/private_key.pem -pubout -out /app/public_key.pem

ENV DB_PASSWORD=331711298a486a7d949140a3030696875d3ede373036a0fcf39ee54c0e146b7c \
	ADMIN_PASSWORD=0f3d3cd133ca1ee99d9041df6d59ae35896ba554177ef81d0ee29095fabfb32a \
	LISTEN_PORT=80
EXPOSE 80
VOLUME /tmp /var/ /run