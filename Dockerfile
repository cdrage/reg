FROM golang:latest 

ENV PATH /go/bin:/usr/local/go/bin:$PATH
ENV GOPATH /go

RUN mkdir /go
ADD . /go/src/github.com/cdrage/reg
WORKDIR /go/src/github.com/cdrage/reg

RUN go build -o reg-server ./server

ENTRYPOINT ["./reg-server"]
CMD ["--help"]
