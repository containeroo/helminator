FROM python:3.7-alpine

ADD requirements.txt helminator.py /app/

RUN apk add --no-cache --virtual .build-deps gcc musl-dev

RUN apk add libc-dev && \
    pip install -r /app/requirements.txt

RUN apk del .build-deps gcc musl-dev

ENTRYPOINT ['python', '/app/helminator.py']
