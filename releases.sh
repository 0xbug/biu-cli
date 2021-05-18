CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '-w -s' -gcflags '-N -l' -o bin/biu-cli_linux_amd64 cmd/biu-cli.go
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags '-w -s' -gcflags '-N -l' -o bin/biu-cli_win_amd64.exe cmd/biu-cli.go
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags '-w -s' -gcflags '-N -l' -o bin/biu-cli_darwin_amd64 cmd/biu-cli.go