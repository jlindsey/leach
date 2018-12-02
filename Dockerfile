FROM golang:latest AS build

RUN go get -u -v github.com/gobuffalo/packr/v2/packr2
COPY . /app
WORKDIR /app
ENV GOOS=linux
RUN make clean release

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=build /app/bin/release/leach /
CMD ["/leach"]
