FROM docker.io/library/golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/iam ./cmd/iam \
 && CGO_ENABLED=0 go build -trimpath -o /out/demo-api ./cmd/demo-api

FROM docker.io/library/alpine:3.22
RUN adduser -D -u 10001 iam && mkdir /data && chown iam /data
COPY --from=build /out/ /usr/local/bin/
COPY config /etc/iam
USER iam
ENV IAM_CONFIG=/etc/iam/dev.json \
    IAM_SIGNING_KEY_FILE=/data/signing-key.pem
VOLUME /data
EXPOSE 4010 4011
CMD ["iam"]
