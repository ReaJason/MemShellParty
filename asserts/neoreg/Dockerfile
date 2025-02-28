FROM python:3.12-slim

WORKDIR /app

RUN pip install requests

COPY neoreg.py .

CMD ["tail", "-f", "/dev/null"]