FROM python:3.12-slim

RUN apt-get update

RUN mkdir /ugt
RUN mkdir /ugt/goosey
COPY setup.py /ugt
COPY requirements.txt /ugt
COPY goosey /ugt/goosey
WORKDIR /ugt

RUN pip install .

RUN mkdir /workdir
WORKDIR /workdir

CMD ["goosey"]
