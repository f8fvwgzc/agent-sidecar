FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/orders .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/orders /orders
EXPOSE 8080
ENTRYPOINT ["/orders"]
