FROM golang:latest 
RUN mkdir /app 
ADD . /app/ 
WORKDIR /app 

RUN cd server && \
    go build -o main . 

ENTRYPOINT ["/app/server/reg-server"]
CMD ["--help"]
