# Go Memory Dumper
This is a simple tool to dump the memory of a running process. Into a file. It is written in Go and uses the cgo (C code in Go) to interact with the system API.

This tool was created as a practice to learn how to interact with the system API using Go and C. Also will be add it to my [go-shield](https://github.com/solrac97gr/go-shield) tool in the near future (when will work for Linux, Windows and Mac).

## Requirements
- Go 1.16 or higher
- GCC or Clang
- Linux System

## Usage
```bash
go run main.go <pid>
```

## Example
```bash
go run main.go 1234
```

## For what?
This tool is useful for debugging purposes. It can be used to dump the memory of a running process and analyze it later. It can be used to debug a running process, to analyze the memory of a process, to analyze the memory of a process that is running on a remote machine, etc.

Use strings, hexdump, or any other tool to analyze the memory dump.
```bash
strings dump.bin | grep -i password
```

## License
MIT