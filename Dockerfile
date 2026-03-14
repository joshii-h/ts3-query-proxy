FROM python:3.12-slim

RUN pip install --no-cache-dir asyncssh

COPY proxy.py /app/proxy.py
WORKDIR /app

EXPOSE 10011

CMD ["python", "-u", "proxy.py"]
