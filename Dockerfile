FROM ubuntu:22.10
FROM python:3.12.6

WORKDIR /cage

COPY . /cage

RUN pip install -e .

ENTRYPOINT ["python", "/cage/CybORG/Evaluation/validation.py"]

