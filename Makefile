VERSION ?= dev
PLATFORMS := linux/amd64 linux/arm64

.PHONY: build release-build test lint fmt vet tidy clean fix

build:
	go build -o bin/scanner ./cmd/scanner

# release-build cross-compiles one binary per PLATFORMS entry into dist/.
# Linux-only: the scanner shells out to apt/rpm/apk, none of which exist
# on macOS or Windows, so binaries for those OSes would never do anything.
release-build:
	rm -rf dist
	mkdir -p dist
	for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		echo "building $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -o dist/scanner_$(VERSION)_$${os}_$${arch} ./cmd/scanner; \
	done

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
