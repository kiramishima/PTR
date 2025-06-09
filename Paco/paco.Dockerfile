FROM python:3.13.0-bookworm

RUN pip install -U pip
RUN pip install pipenv

WORKDIR /app

# Copiamos hacia el directorio /app
COPY ["./Pipfile", "./Pipfile.lock", "./"]

# Instalamos las librerias
RUN pipenv install --system --deploy


COPY ["./app.py", "./assistant.py", "./db.py", "./.env", "./ingest.py", "./minsearch.py", "./prep_data.py", "./"]

EXPOSE 9696

# Ejecutamos el servicio de Flask con Gunicorn
ENTRYPOINT ["gunicorn", "--bind=0.0.0.0:9696", "app:app"]