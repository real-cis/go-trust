# go-trust

Go library for Intel TDX trust and attestation, with packages to parse eventlog, measure firmware, and generate quotes.

## Packages

* ccel - Parse and replay CC Event Logs (CCEL) including TCG and IMA logs. Extract RTMR measurements and verify Secure Boot variables.

* tdvf - Measure TD Virtual Firmware (TDVF) images. Build MRTD values and extract Secure Boot variable measurements from firmware binaries.

* sgx - parses and verifies for tcb status for V3 SGX quotes.

* tdx - Generate and parse TDX quotes for attestation.(uses go-tdx-guest lib from Google)


## Usage

```go
import (
    "gitlab.com/real-cis/cc/go-trust/ccel"
    "gitlab.com/real-cis/cc/go-trust/tdvf"
    "gitlab.com/real-cis/cc/go-trust/tdx"
)
```

Parse event logs, measure firmware images, or generate attestation quotes using the exported types and functions from each package.

