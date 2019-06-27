FROM python:3
ENV PYTHONUNBUFFERED 1

RUN mkdir -p /webapp
WORKDIR /webapp

COPY requirements.txt /webapp/
RUN pip install -r requirements.txt

COPY app.py database.py models.py /webapp/

EXPOSE 5000
ENV FLASK_APP=app.py
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0"]
#CMD ["python", "/webapp/app.py"]
#CMD ["tail", "-f", "/dev/null"]
