FROM registry.centos.org/centos/golang:latest

#ENV PATH /go/bin:/usr/local/go/bin:$PATH
#ENV GOPATH /go

RUN mkdir /src

COPY . /go/src/reg
RUN cd /go/src/reg/server && \
    go get -v && \
    go build && \
    mv server /src/server

COPY reg/static /src/static
COPY reg/templates /src/templates

WORKDIR /src

EXPOSE 8080
ENTRYPOINT ["./server"]
CMD ["--help"]
