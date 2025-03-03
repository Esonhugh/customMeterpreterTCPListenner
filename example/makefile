GOFLAGGER=-ldflags '-extldflags "-static -fPIC" -linkmode=external -s -w' -buildmode=pie -tags 'osusergo netgo static_build nomsgpack noproto novalidator fts5 '
# GOFLAGGER=-compiler gccgo --gccgoflags "-static"
# GOFLAGGER=-buildmode=pie
GOENVS=CC=musl-gcc GOOS=linux GOARCH=amd64 CGO_ENABLED=1 # CGO_LDFLAGS="-static"

build:
	$(GOENVS) go build $(GOFLAGGER) -o shellcode.elf ./main.go && file shellcode.elf