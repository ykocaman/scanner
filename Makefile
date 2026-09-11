.PHONY: build test lint fmt vet tidy clean fix

build:
	go build -o bin/scanner ./cmd/scanner

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run

fmt:
	gofumpt -l -w .
	goimports -w .

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf bin/

fix:
	go run golang.org/x/tools/go/analysis/passes/modernize/cmd/modernize@latest -fix -test \
		-any -atomictypes -embedlit -errorsastype -forvar -mapsloop -minmax \
		-newexpr -plusbuild -rangeint -reflecttypefor -slicesbackward \
		-slicescontains -slicessort -stringsbuilder -stringscut \
		-stringscutprefix -stringsseq -testingcontext -waitgroupgo ./...
	gofumpt -l -w .
	goimports -w .
	golangci-lint run --fix ./...
