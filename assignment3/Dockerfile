FROM python:3.8

COPY /app /app

WORKDIR /app

RUN pip install Flask bcrypt authlib requests pyotp qrcode[pil]


EXPOSE 80

CMD ["python", "main.py"]