FROM python:3.10
COPY . /srv
WORKDIR /srv
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "sigsum-witness.py"]
