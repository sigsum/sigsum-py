FROM python:3.10
WORKDIR /srv/sigsum-witness
COPY . /srv/sigsum-witness
RUN pip install --no-cache-dir .
ENTRYPOINT ["sigsum-witness"]
