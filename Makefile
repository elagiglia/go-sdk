utest:
	export GOPATH=export PWD=`pwd`
	go test -v src/github.com/mercadolibre/sdk/* 2>&1

deploy:
	export GOPATH=export PWD=`pwd`
	go build -v github.com/mercadolibre/sdk/

test:
	${MAKE} utest
	${MAKE} kill


.PHONY: test utest deploy
