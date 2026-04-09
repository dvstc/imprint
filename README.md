# Imprint

Imprint is a Go library for device enrollment, certificate renewal, and mutual TLS (mTLS) authentication. It provides a complete device-to-service trust establishment protocol:

1. **Fingerprint** - generate a unique, stable identity for a device from hardware attributes
2. **Enroll** - prove device authenticity and receive a signed client certificate
3. **Renew** - automatically renew certificates before or after expiry via a three-tier fallback
4. **Authenticate** - use mTLS for all subsequent communication

## Installation

```bash
go get github.com/dvstc/imprint
```

## Packages

- **`imprint`** (root) - shared types (`EnrollmentRequest`, `EnrollmentResponse`, `Enrollment`, `RenewalRequest`, `ChallengeRenewalRequest`)
- **`imprint/fingerprint`** - hardware fingerprint generation with tiered fallback (hardware, persisted, generated)
- **`imprint/client`** - client-side enrollment, certificate renewal, auto-renewal, certificate inspection, and mTLS configuration (`enroll.go`, `renew.go`, `cert.go`, `autorenew.go`, `tls.go`, `store.go`)
- **`imprint/server`** - server-side enrollment handling, renewal handlers, internal CA, and mTLS verification middleware (`handler.go`, `renew.go`, `verifier.go`, `ca.go`, `store.go`)

## How It Works

### Enrollment

```
Device                                    Service
  |                                          |
  |-- Generate fingerprint (hardware hash)   |
  |-- Generate ECDSA P-256 keypair + CSR     |
  |                                          |
  |-- POST /enroll  ----------------------->|
  |   { build_secret, fingerprint, csr }     |-- Validate build secret
  |                                          |-- Sign CSR with internal CA
  |<-- { server_id, certificate, ca_cert } --|
  |                                          |
  |-- All future requests via mTLS -------->|
  |   (private key never leaves device)      |
```

### Certificate Renewal (Three-Tier Fallback)

| Tier | Situation                     | Endpoint                        | Auth mechanism                |
| ---- | ----------------------------- | ------------------------------- | ----------------------------- |
| 1    | Cert valid, nearing expiry    | `POST /api/v1/renew` (mTLS)    | TLS client cert               |
| 2    | Cert expired (within 30 days) | `POST /api/v1/renew/challenge`  | Signature proof + fingerprint |
| 3    | Key lost or device rebuilt    | `POST /api/v1/enroll`           | Build secret + fingerprint    |

```
Device                                    Service
  |                                          |
  |-- Check cert expiry                      |
  |                                          |
  |  [Tier 1: cert still valid]              |
  |-- POST /renew (mTLS) ----------------->|
  |   { csr }                                |-- Verify mTLS identity
  |                                          |-- Sign new CSR, update serial
  |<-- { server_id, certificate, ca_cert } --|
  |                                          |
  |  [Tier 2: cert expired, within window]   |
  |-- POST /renew/challenge (HTTPS) ------->|
  |   { server_id, fingerprint,              |-- Verify proof signature
  |     expired_cert, csr, proof }           |-- Verify fingerprint + serial
  |<-- { server_id, certificate, ca_cert } --|
  |                                          |
  |  [Tier 3: fallback to re-enrollment]     |
  |-- POST /enroll (HTTPS) ---------------->|
  |   (same as initial enrollment)           |
```

## Usage

### Client side (device)

```go
import (
    "github.com/dvstc/imprint/client"
    "github.com/dvstc/imprint/fingerprint"
)

// Generate hardware fingerprint
fp, err := fingerprint.Generate(fingerprint.Options{
    PersistDir: "/data/imprint",
})

// Enroll with the service
resp, err := client.Enroll(ctx, client.EnrollConfig{
    ServiceURL:  "https://updates.example.com",
    BuildSecret: buildSecret,
    Fingerprint: fp.Fingerprint,
    Hostname:    hostname,
    OS:          runtime.GOOS,
    Arch:        runtime.GOARCH,
    StoreDir:    "/etc/myapp/imprint",
})

// Load mTLS config for subsequent requests
tlsCfg, err := client.LoadTLS("/etc/myapp/imprint")
httpClient := &http.Client{
    Transport: &http.Transport{TLSClientConfig: tlsCfg},
}
```

#### Certificate Renewal

```go
// Check if renewal is needed
needs, err := client.NeedsRenewal("/etc/myapp/imprint", 30*24*time.Hour)

// Tier 1: mTLS renewal (cert still valid)
resp, err := client.Renew(ctx, client.RenewConfig{
    ServiceURL: "https://updates.example.com",
    StoreDir:   "/etc/myapp/imprint",
})

// Automatic three-tier renewal with fallback
action, err := client.RenewOrReenroll(ctx,
    client.RenewConfig{
        ServiceURL:      "https://updates.example.com",
        StoreDir:        "/etc/myapp/imprint",
        ChallengeWindow: 30 * 24 * time.Hour,
    },
    client.EnrollConfig{
        ServiceURL:  "https://updates.example.com",
        BuildSecret: buildSecret,
        Fingerprint: fp.Fingerprint,
        StoreDir:    "/etc/myapp/imprint",
    },
    30*24*time.Hour, // renewal threshold
)
// action: "renewed", "challenge_renewed", "reenrolled", or "none"
```

#### Background Auto-Renewal (Long-Running Services)

```go
// Use ReloadableTLS for automatic cert pickup after renewal
tlsCfg, err := client.ReloadableTLS("/etc/myapp/imprint")
httpClient := &http.Client{
    Transport: &http.Transport{TLSClientConfig: tlsCfg},
}

// Start background auto-renewer
renewer := client.NewAutoRenewer(client.AutoRenewerConfig{
    RenewConfig:   client.RenewConfig{
        ServiceURL: "https://updates.example.com",
        StoreDir:   "/etc/myapp/imprint",
    },
    EnrollConfig:  enrollCfg,
    CheckInterval: 24 * time.Hour,
    Threshold:     30 * 24 * time.Hour,
    OnRenew:       func(action string) { log.Printf("renewed: %s", action) },
    OnError:       func(err error) { log.Printf("renewal error: %v", err) },
})

ctx, cancel := context.WithCancel(context.Background())
defer cancel()
go renewer.Start(ctx) // blocks until context is cancelled
```

### Server side (service)

```go
import "github.com/dvstc/imprint/server"

// Initialize CA
ca, err := server.NewCA(server.CAConfig{
    CertDir:      "./imprint-ca",
    Organization: "My Service",
})

// Public endpoints (no mTLS required)
mux.Handle("POST /api/v1/enroll", server.NewEnrollHandler(server.EnrollConfig{
    CA:           ca,
    Store:        myStore, // implements server.Store
    BuildSecrets: []string{secret},
    Mode:         imprint.ModeAuto,
}))
mux.Handle("POST /api/v1/renew/challenge", server.NewChallengeRenewHandler(server.ChallengeRenewConfig{
    CA:              ca,
    Store:           myStore,
    ChallengeWindow: 30 * 24 * time.Hour,
}))

// mTLS-protected endpoints
mux.Handle("POST /api/v1/renew", server.RequireMTLS(myStore, server.NewRenewHandler(server.RenewConfig{
    CA:    ca,
    Store: myStore,
})))
mux.Handle("GET /api/v1/data", server.RequireMTLS(myStore, dataHandler))
```

## Cross-Language Compatibility

Imprint is protocol-first. The enrollment flow uses standard HTTP+JSON and X.509 certificates. Any language that can make HTTPS requests and handle PEM certificates can implement a compatible client. See [DESIGN.md](DESIGN.md) for the full protocol specification, fingerprint computation spec, and cross-language integration approaches.

## License

MIT - see [LICENSE](LICENSE).
