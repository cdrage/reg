FROM registry.centos.org/centos/golang:latest

ENV PATH /go/bin:/usr/local/go/bin:/opt/rh/go-toolset-7/root/usr/bin:/opt/rh/go-toolset-7/root/usr/sbin:/usr/local/sbin:$PATH
ENV GOPATH /go:/go:/opt/rh/go-toolset-7/root/usr/share/gocode:/opt/rh/go-toolset-7/root/usr/share/gocode:$GOPATH

RUN mkdir /src

COPY . /go/src/reg
RUN cd /go/src/reg/server && \
    go get -v && \
    go build && \
    mv server /src/server

COPY server/static /src/static
COPY server/templates /src/templates

WORKDIR /src

EXPOSE 8080
ENTRYPOINT ["./server"]
CMD ["--help"]
