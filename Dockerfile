FROM golang:1.15 AS build
ENV CGO_ENABLED=0 GOOS=linux
WORKDIR /build/
ADD . /build/
RUN go build -a -installsuffix cgo -o scanner

# FROM ubuntu:21.04 AS final
FROM ubuntu:14.04 AS final
COPY --from=build /build/scanner /bin/scanner
CMD "/bin/scanner"