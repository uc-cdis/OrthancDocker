FROM jodogne/orthanc-python:1.10.1

RUN apt update -y \
    && apt upgrade -y \
    && apt install -y python3-pip

COPY ./requirements.txt ./requirements.txt
RUN pip3 install -r ./requirements.txt
RUN rm ./requirements.txt

COPY ./authz_filter.py /etc/orthanc/authz_filter.py
