FROM python:3.13-slim

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

FROM python:3.13-slim as tests
WORKDIR /app
COPY requirements.txt .
RUN apt-get update && apt-get install -y build-essential
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt
COPY goosey/ goosey/
COPY tests/ tests/
RUN ls -al
CMD ["bash"]
# ENTRYPOINT [ "python", "-m", "pytest", "tests/test_suite.py"]
