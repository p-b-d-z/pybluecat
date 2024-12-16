FROM python:3.11-bullseye

ENV AWS_ACCESS_KEY_ID ""
ENV AWS_SECRET_ACCESS_KEY ""
ENV AWS_DEFAULT_PROFILE ""
ENV BLUECAT_HOST ""
ENV BLUECAT_USER ""
ENV BLUECAT_PASS ""
ENV BLUECAT_CFG ""
ENV REGION ""
ENV ENVIRONMENT ""

COPY . .

RUN pip3 install --no-color -r build/requirements.txt && \
    pip3 install .
