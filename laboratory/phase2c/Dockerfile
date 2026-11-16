FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables openssl \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir idna==3.20 dnspython==2.9.2
WORKDIR /lab
ENV PYTHONPATH=/lab PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY app/services/web_target_policy.py app/services/web_target_transport.py app/services/controlled_dns.py /lab/app/services/
COPY laboratory/phase2c/ /lab/laboratory/phase2c/
ARG LAB_CERT_NONCE
RUN mkdir /lab/certs && cd /lab/certs \
    && openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=VulnTrack-Phase2C-LAB-CA -keyout ca.key -out ca.pem \
    && openssl req -newkey rsa:2048 -nodes -subj /CN=control.example.net -keyout server.key -out server.csr \
    && printf 'subjectAltName=DNS:control.example.net,DNS:v6.example.net\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > server.ext \
    && openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 1 -extfile server.ext -out server.pem \
    && rm ca.key && chmod 600 server.key && chmod 644 *.pem
USER 65532:65532
CMD ["sleep", "600"]
