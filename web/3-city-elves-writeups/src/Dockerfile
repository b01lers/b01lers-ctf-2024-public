#put your dockerfile contents here
from python:3.11

WORKDIR /

COPY challenge /app
COPY requirements.txt .
COPY flag.png .

RUN apt-get update && apt-get upgrade && apt-get install sqlite3 -y
RUN pip install -I --no-cache-dir -r requirements.txt --break-system-packages

EXPOSE 5000

WORKDIR /app

CMD ["python3", "-m", "flask", "run", "--host=0.0.0.0"]
