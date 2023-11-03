FROM python:3.8

COPY /app /app
COPY requirements.txt /app/
WORKDIR /app

RUN pip install --upgrade pip
RUN pip install -r requirements.txt


EXPOSE 80

CMD ["python", "main.py"]