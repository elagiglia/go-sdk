utest:
	export GOPATH=$(shell pwd)
	go test -v src/github.com/mercadolibre/sdk/* 2>&1

deploy:
	export GOPATH=$(shell pwd)
	go build -v src/github.com/mercadolibre/sdk/
build:
	export GOPATH=$(shell pwd)
	go build -o main src/github.com/mercadolibre/*go

test:
	${MAKE} utest


.PHONY: test utest deploy
