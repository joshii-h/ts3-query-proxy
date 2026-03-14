FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir .
COPY proxy.py .

EXPOSE 10011
CMD ["python", "-u", "proxy.py"]
