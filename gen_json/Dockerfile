FROM alpine

COPY gen_auth_json.sh /
RUN chmod a+x /gen_auth_json.sh

CMD ["/gen_auth_json.sh", "/authfiles/auth-image.json"]
