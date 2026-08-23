# swinv - Local Software Inventory Collector
#
# Targets:
#   build          static binary at bin/swinv
#   test           unit tests with the race detector
#   lint           go vet, plus golangci-lint when installed
#   golden         regenerate the checked-in golden files from testdata/rootfs
#   bench          time and measure peak RSS of a scan over testdata/rootfs
#   licenses       generate THIRD_PARTY_LICENSES.md from the dependency graph
#   license-check  fail if any dependency licence is GPL/AGPL/LGPL/unknown
#   release        cross-compile linux/amd64 + linux/arm64 and write SHA256SUMS
#   clean          remove build, coverage and benchmark artefacts

# --- toolchain -------------------------------------------------------------
# This box keeps Go 1.26.6 outside the default PATH. Prepend it when it is
# actually there; otherwise fall through to whatever `go` the caller has.
ifneq ($(wildcard /usr/local/go/bin/go),)
export PATH := /usr/local/go/bin:$(PATH)
endif

GO ?= go

# --- version stamping ------------------------------------------------------
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null)
ifeq ($(strip $(VERSION)),)
VERSION := dev
endif

COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null)
ifeq ($(strip $(COMMIT)),)
COMMIT := none
endif

# --- layout ----------------------------------------------------------------
BIN_DIR      := bin
BINARY       := $(BIN_DIR)/swinv
PKG          := ./cmd/swinv
FIXTURE_ROOT := testdata/rootfs
BENCH_OUT    := $(BIN_DIR)/bench-out
LICENSE_CSV  := $(BIN_DIR)/licenses.csv
LICENSE_DOC  := THIRD_PARTY_LICENSES.md
LICENSE_ALLOWLIST := licenses-allowlist.txt
DIST_DIR     := dist
NFPM_CONFIG  := packaging/nfpm.yaml

# Package version: strip a leading "v" and replace the "-" that git describe
# inserts, because rpm rejects "-" in a version field.
PKG_VERSION  := $(shell echo "$(VERSION)" | sed -e 's/^v//' -e 's/-/./g')
PKG_ARCH     ?= amd64

# nfpm is a build tool, not a module dependency, so it never enters go.mod.
# Pinned, and kept in step with .github/workflows/release.yml: an unpinned
# build tool can change what ships in a package between two builds of one tag.
# Install once with: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VERSION)
NFPM_VERSION ?= v2.47.0
NFPM ?= $(shell command -v nfpm 2>/dev/null || echo "$(GO) run github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VERSION)")

LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

RELEASE_PLATFORMS := linux/amd64 linux/arm64

# go-licenses is not a module dependency; it is fetched on demand so it never
# lands in go.mod. To avoid the download on every invocation, install it once:
#
#     go install github.com/google/go-licenses@v1.6.0
#
# and this Makefile will pick the installed binary up from PATH automatically.
GO_LICENSES_VERSION ?= v1.6.0
GO_LICENSES ?= $(shell command -v go-licenses 2>/dev/null || echo "$(GO) run github.com/google/go-licenses@$(GO_LICENSES_VERSION)")

.DEFAULT_GOAL := build
.PHONY: all build test lint golden bench licenses license-check release clean help \
	deb rpm packages packages-verify

all: build

# --- build -----------------------------------------------------------------
build:
	@echo ">> building $(BINARY) (version=$(VERSION) commit=$(COMMIT))"
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

# --- test ------------------------------------------------------------------
test:
	$(GO) test -race ./...

# --- lint ------------------------------------------------------------------
lint:
	$(GO) vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
	    echo ">> golangci-lint run"; \
	    golangci-lint run; \
	else \
	    echo ">> golangci-lint not installed, skipping"; \
	    echo ">> install it with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# --- golden files ----------------------------------------------------------
# Regenerates the checked-in golden JSON/CSV by scanning the fixture rootfs
# with the freshly built binary. Review the diff before committing.
golden: build
	@test -d $(FIXTURE_ROOT) || { echo "missing fixture tree $(FIXTURE_ROOT)" >&2; exit 1; }
	@echo ">> regenerating golden files from $(FIXTURE_ROOT)"
	SWINV_UPDATE_GOLDEN=1 \
	INVD_BINARY=$(abspath $(BINARY)) \
	INVD_FIXTURE_ROOT=$(abspath $(FIXTURE_ROOT)) \
	$(GO) test ./... -run 'Golden' -count=1

# --- benchmark -------------------------------------------------------------
# Wall time and peak RSS for a scan of the fixture tree. GNU time is used when
# available; otherwise the target degrades to wall-clock only.
bench: build
	@test -d $(FIXTURE_ROOT) || { echo "missing fixture tree $(FIXTURE_ROOT)" >&2; exit 1; }
	@mkdir -p $(BENCH_OUT)
	@if /usr/bin/time -v true >/dev/null 2>&1; then \
	    echo ">> benchmarking $(BINARY) against $(FIXTURE_ROOT) (GNU /usr/bin/time -v)" >&2; \
	    /usr/bin/time -v -o $(BIN_DIR)/bench.time \
	        $(BINARY) --root $(FIXTURE_ROOT) --out $(BENCH_OUT) --no-auto-exclude-mounts --quiet; \
	    grep -E 'Elapsed \(wall clock\)|Maximum resident set size|User time|System time' \
	        $(BIN_DIR)/bench.time >&2 || cat $(BIN_DIR)/bench.time >&2; \
	else \
	    echo ">> GNU time (-v) unavailable; reporting wall clock only, peak RSS omitted" >&2; \
	    start=$$(date +%s%N); \
	    $(BINARY) --root $(FIXTURE_ROOT) --out $(BENCH_OUT) --no-auto-exclude-mounts --quiet; \
	    end=$$(date +%s%N); \
	    echo "Elapsed (wall clock): $$(( (end - start) / 1000000 )) ms" >&2; \
	    echo "Maximum resident set size: unavailable (install GNU time)" >&2; \
	fi

# --- licences --------------------------------------------------------------
# Depends on the module graph: without these prerequisites a stale licence
# inventory would satisfy license-check after a dependency was added.
$(LICENSE_CSV): go.mod go.sum
	@mkdir -p $(BIN_DIR)
	@echo ">> collecting dependency licences with go-licenses (CGO_ENABLED=0)"
	@# CGO_ENABLED=0 matters: go-licenses walks the build graph, so a cgo-only
	@# dependency such as github.com/DataDog/zstd appears with cgo enabled and
	@# vanishes without it. The shipped binary is always built CGO_ENABLED=0,
	@# so the inventory must describe that build or it drifts between a
	@# developer machine and CI.
	@CGO_ENABLED=0 $(GO_LICENSES) csv $(PKG) > $@ || { rm -f $@; \
	    echo "go-licenses failed; see the output above" >&2; exit 1; }

licenses: $(LICENSE_CSV) license-check
	@echo ">> writing $(LICENSE_DOC)"
	@{ \
	    echo "# Third-party licences"; \
	    echo; \
	    echo "Generated by \`make licenses\` from the module graph of \`$(PKG)\`."; \
	    echo "Do not edit by hand."; \
	    echo; \
	    echo "swinv is Apache-2.0. **No dependency below is GPL, AGPL or LGPL**;"; \
	    echo "\`make license-check\` enforces that in CI and fails the build otherwise."; \
	    echo; \
	    echo "A licence shown as \`Unknown\` means go-licenses could not classify the"; \
	    echo "text automatically, not that the licence is unknown to us. Every such"; \
	    echo "entry has been read by a human and recorded, with the licence actually"; \
	    echo "found and where it was read from, in \`licenses-allowlist.txt\`. An"; \
	    echo "allowlist entry only suppresses an unclassifiable licence and can never"; \
	    echo "suppress a detected copyleft one."; \
	    echo; \
	    echo "| Module | Licence | Source |"; \
	    echo "|---|---|---|"; \
	    LC_ALL=C sort -t, -k1,1 $(LICENSE_CSV) | awk -F, 'NF { url=$$2; \
	        if (url == "" || url == "Unknown" || url !~ /^https?:\/\//) url="-"; \
	        else url="[link](" url ")"; \
	        printf "| `%s` | %s | %s |\n", $$1, $$3, url }'; \
	} > $(LICENSE_DOC)
	@echo ">> $(LICENSE_DOC) written ($$(grep -c '^| ' $(LICENSE_DOC)) rows)"

# Hard gate from spec section 3. CI calls this target directly.
license-check: $(LICENSE_CSV)
	@echo ">> checking dependency licences for GPL / AGPL / LGPL / unknown"
	@bad=$$(awk -F, -v allow="$(LICENSE_ALLOWLIST)" '\
	    BEGIN { \
	        while ((getline line < allow) > 0) { \
	            sub(/#.*/, "", line); \
	            n = split(line, f, /[ \t]+/); \
	            if (n > 0 && f[1] != "") allowed[f[1]] = 1; \
	        } \
	    } \
	    NF { \
	        mod = $$1; lic = $$3; \
	        gsub(/^[ \t]+|[ \t]+$$/, "", lic); \
	        gsub(/^[ \t]+|[ \t]+$$/, "", mod); \
	        low = tolower(lic); \
	        copyleft = (low ~ /gpl/); \
	        unknown  = (lic == "" || low ~ /unknown/); \
	        if (copyleft) { \
	            printf "  %s: %s (copyleft - NOT allowlistable)\n", mod, lic; \
	        } else if (unknown && !(mod in allowed)) { \
	            printf "  %s: %s\n", mod, (lic == "" ? "(no licence detected)" : lic); \
	        } \
	    }' $(LICENSE_CSV)); \
	if [ -n "$$bad" ]; then \
	    echo "FAIL: forbidden or undetermined dependency licences:" >&2; \
	    echo "$$bad" >&2; \
	    echo "" >&2; \
	    echo "swinv must stay free of GPL/AGPL/LGPL code (spec section 3)." >&2; \
	    echo "If a licence is merely UNRECOGNISED, read the actual LICENSE file and," >&2; \
	    echo "if it is genuinely permissive, add an audited entry to $(LICENSE_ALLOWLIST)." >&2; \
	    echo "A detected GPL/AGPL/LGPL can never be allowlisted - remove the dependency." >&2; \
	    exit 1; \
	fi; \
	echo "OK: every dependency licence is permissive and identified"

# --- packaging -------------------------------------------------------------
# The man page is shipped gzipped, which is what both Debian and RPM expect.
$(DIST_DIR)/man/swinv.8.gz: packaging/swinv.8
	@mkdir -p $(DIST_DIR)/man
	@gzip -9 -n -c $< > $@

deb: build $(DIST_DIR)/man/swinv.8.gz $(LICENSE_DOC)
	@mkdir -p $(DIST_DIR) $(BIN_DIR)
	@echo ">> building $(DIST_DIR)/swinv_$(PKG_VERSION)_$(PKG_ARCH).deb"
	@PKG_VERSION=$(PKG_VERSION) PKG_ARCH=$(PKG_ARCH) \
	    $(NFPM) package -f $(NFPM_CONFIG) -p deb -t $(DIST_DIR)

rpm: build $(DIST_DIR)/man/swinv.8.gz $(LICENSE_DOC)
	@mkdir -p $(DIST_DIR) $(BIN_DIR)
	@echo ">> building $(DIST_DIR)/swinv-$(PKG_VERSION).$(PKG_ARCH).rpm"
	@PKG_VERSION=$(PKG_VERSION) PKG_ARCH=$(PKG_ARCH) \
	    $(NFPM) package -f $(NFPM_CONFIG) -p rpm -t $(DIST_DIR)

packages: deb rpm
	@echo ">> packages in $(DIST_DIR):"
	@ls -1 $(DIST_DIR)/*.deb $(DIST_DIR)/*.rpm 2>/dev/null

# Inspect the built packages without installing them. Uses whichever of
# dpkg-deb / rpm happens to be present, so it degrades on either family.
packages-verify:
	@for p in $(DIST_DIR)/*.deb; do \
	    [ -e "$$p" ] || continue; \
	    echo ">> $$p"; \
	    if command -v dpkg-deb >/dev/null 2>&1; then \
	        dpkg-deb --info "$$p" | sed -n '1,12p'; \
	        echo "   contents:"; dpkg-deb --contents "$$p" | awk '{print "     "$$NF}'; \
	    else echo "   dpkg-deb not installed, skipping"; fi; \
	done
	@for p in $(DIST_DIR)/*.rpm; do \
	    [ -e "$$p" ] || continue; \
	    echo ">> $$p"; \
	    if command -v rpm >/dev/null 2>&1; then \
	        rpm -qip "$$p" 2>/dev/null | sed -n '1,14p'; \
	        echo "   contents:"; rpm -qlp "$$p" 2>/dev/null | sed 's/^/     /'; \
	    else echo "   rpm not installed, skipping"; fi; \
	done

# --- release ---------------------------------------------------------------
# Produces everything a GitHub release needs, into dist/:
#   swinv-<version>-linux-<arch>          static binaries
#   swinv_<version>-1_<arch>.deb          Debian/Ubuntu packages
#   swinv-<version>-1.<rpmarch>.rpm       RHEL/Fedora/SUSE packages
#   SHA256SUMS                            checksums over all of the above
RELEASE_ARCHES := amd64 arm64

# Each binary is published twice: once carrying the version, and once without
# it. The version-less name is what makes
#   https://github.com/chaugan/swinv/releases/latest/download/swinv-linux-amd64
# resolve for every release, so install instructions never carry a version
# number that goes stale the moment the next tag lands. Same bytes, second name.

release: $(DIST_DIR)/man/swinv.8.gz $(LICENSE_DOC)
	@mkdir -p $(DIST_DIR) $(BIN_DIR)
	@rm -f $(DIST_DIR)/SHA256SUMS
	@for arch in $(RELEASE_ARCHES); do \
	    out=$(DIST_DIR)/swinv-$(VERSION)-linux-$$arch; \
	    echo ">> building $$out"; \
	    CGO_ENABLED=0 GOOS=linux GOARCH=$$arch \
	        $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $$out $(PKG) || exit 1; \
	    cp $$out $(DIST_DIR)/swinv-linux-$$arch || exit 1; \
	    echo ">> packaging $$arch"; \
	    cp $$out $(BIN_DIR)/swinv || exit 1; \
	    PKG_VERSION=$(PKG_VERSION) PKG_ARCH=$$arch \
	        $(NFPM) package -f $(NFPM_CONFIG) -p deb -t $(DIST_DIR) || exit 1; \
	    PKG_VERSION=$(PKG_VERSION) PKG_ARCH=$$arch \
	        $(NFPM) package -f $(NFPM_CONFIG) -p rpm -t $(DIST_DIR) || exit 1; \
	done
	@# Windows: a binary only, no package. There is no .deb or .rpm to build,
	@# and shipping an MSI would claim a maturity the Windows collector has
	@# not earned -- see docs/WINDOWS.md for what it does not yet cover.
	@out=$(DIST_DIR)/swinv-$(VERSION)-windows-amd64.exe; \
	echo ">> building $$out"; \
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
	    $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $$out $(PKG) || exit 1; \
	cp $$out $(DIST_DIR)/swinv-windows-amd64.exe || exit 1
	@echo ">> restoring the native build in $(BIN_DIR)"
	@$(MAKE) --no-print-directory build
	@echo ">> writing $(DIST_DIR)/SHA256SUMS"
	@cd $(DIST_DIR) && \
	if command -v sha256sum >/dev/null 2>&1; then \
	    sha256sum swinv-* swinv_* 2>/dev/null > SHA256SUMS; \
	else \
	    shasum -a 256 swinv-* swinv_* 2>/dev/null > SHA256SUMS; \
	fi
	@cat $(DIST_DIR)/SHA256SUMS

# --- housekeeping ----------------------------------------------------------
clean:
	rm -rf $(BIN_DIR)
	rm -rf $(DIST_DIR)
	rm -f coverage.out coverage.html coverage.txt
	rm -rf $(BENCH_OUT)

help:
	@echo "targets: build test lint golden bench licenses license-check"
	@echo "         deb rpm packages packages-verify release clean"
