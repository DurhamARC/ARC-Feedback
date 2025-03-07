FROM python:3.13.2-slim-bookworm

ADD requirements.txt .

RUN pip install -r requirements.txt

COPY SearchApp ./

EXPOSE 5000

CMD ["python", "ORCiD_API_App.py"]