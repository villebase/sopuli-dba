# The Linux client of 06_client_library_probe.py: Microsoft's ODBC Driver 18
# and the four Python client libraries the probe measures, at the versions its
# header names. The probe builds it as sopuli-mssql-clients and removes nothing.
FROM python:3.13.18-slim-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl gnupg ca-certificates \
    unixodbc=2.3.11-2+deb12u1 \
 && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
    | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
 && curl -fsSL https://packages.microsoft.com/config/debian/12/prod.list \
    > /etc/apt/sources.list.d/mssql-release.list \
 && apt-get update \
 && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18=18.7.1.1-1 \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir \
    mssql-python==1.17.0 pyodbc==5.5.0 pymssql==2.4.6 python-tds==1.17.1 \
    pyOpenSSL==26.4.0 cryptography==50.0.2 certifi==2026.10.23
WORKDIR /probe
