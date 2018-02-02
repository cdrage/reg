FROM golang:latest 

ENV PATH /go/bin:/usr/local/go/bin:$PATH
ENV GOPATH /go

RUN mkdir /app 
ADD . /app/ 
WORKDIR /app 

RUN go build -o reg-server ./server

ENTRYPOINT ["./reg-server"]
CMD ["--help"]
