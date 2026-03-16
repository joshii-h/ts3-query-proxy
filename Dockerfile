FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml proxy.py ./
RUN pip install --no-cache-dir .

EXPOSE 10011
CMD ["python", "-u", "proxy.py"]
