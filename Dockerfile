FROM python:3.7-alpine

ADD requirements.txt helminator.py /app/

RUN apk add libc-dev && \
    pip install -r /app/requirements.txt

ENTRYPOINT ['python', '/app/helminator.py']
