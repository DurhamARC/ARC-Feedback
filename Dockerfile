FROM python:3.13.2-slim-bookworm

LABEL keep=true

ADD requirements.txt .

RUN python -m pip install --upgrade pip

RUN pip install --no-cache-dir -r requirements.txt

COPY SearchApp ./

EXPOSE 5000

CMD ["sh", "-c", "flask db upgrade && flask run --host=0.0.0.0"]