generate:
	cd pkg/ && go generate ./...

build:
	cd cmd/kprobe/ && go build