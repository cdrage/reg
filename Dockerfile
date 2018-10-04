FROM centos:latest

ENV PATH /go/bin:/usr/local/go/bin:$PATH
ENV GOPATH /go

RUN yum install -y go

RUN go get -v github.com/bamachrn/reg

ENTRYPOINT ["reg-server"]
CMD ["--help"]
