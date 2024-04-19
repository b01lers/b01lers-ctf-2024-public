FROM python:3.11

WORKDIR /

COPY ./src/challenge /app
COPY ./src/requirements.txt .

RUN apt-get update && apt-get upgrade && apt-get install sqlite3
RUN pip install -I --no-cache-dir -r requirements.txt --break-system-packages

EXPOSE 5000

WORKDIR /app

CMD ["python3", "-m", "flask", "run", "--cert=adhoc", "--host=0.0.0.0"]
