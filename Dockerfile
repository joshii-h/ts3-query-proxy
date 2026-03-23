FROM python:3.13-slim

RUN pip install --no-cache-dir asyncssh

WORKDIR /app
COPY proxy.py .

EXPOSE 10011
CMD ["python", "-u", "proxy.py"]
