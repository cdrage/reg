FROM centos:latest

ENV PATH /go/bin:/usr/local/go/bin:$PATH
ENV GOPATH /go

RUN yum install -y go git

RUN mkdir /src

RUN go get -v github.com/bamachrn/reg && \
    cd $GOPATH/src/github.com/bamachrn/reg/server && \
    go build && \
    mv server /src/server

COPY static /src/static
COPY templates /src/templates

WORKDIR /src

EXPOSE 8080
ENTRYPOINT ["./server"]
CMD ["--help"]
