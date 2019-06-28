FROM python:3
ENV PYTHONUNBUFFERED 1

RUN mkdir -p /webapp
WORKDIR /webapp

COPY requirements.txt /webapp/
RUN pip install -r requirements.txt

COPY . /webapp/

EXPOSE 5000
CMD ["uwsgi", "--socket=0.0.0.0:5000", "--uid=1000", "--gid=1000", \
     "--master", "--processes=1", \
     "--manage-script-name", "--mount=/auth=auth_app:app"]

#CMD ["tail", "-f", "/dev/null"]
