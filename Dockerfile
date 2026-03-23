FROM python:3.14-slim

RUN pip install --no-cache-dir asyncssh

WORKDIR /app
COPY proxy.py .

EXPOSE 10011
CMD ["python", "-u", "proxy.py"]
