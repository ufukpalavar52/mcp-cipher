# mcp-cipher

Encrypts and decrypts the secrets the MCP stack stores. gRPC, Go.

**It is the only process that holds the keys.** Every other service stores ciphertext and a
key id; none of them has to be trusted with a key in order to store a secret, and a
database dump on its own reveals nothing.

```
mcp-gateway ──gRPC──▶ mcp-cipher
(ciphertext + key id)   (the keys, and nothing else)
```

## Running

```bash
cp .env.example .env         # then generate a key
export MCP_CIPHER_KEY_V1=$(openssl rand -base64 32)
go run ./cmd
```

It refuses to start without a usable key. A cipher service that starts without one can
only reject every request, and it would reject them at the moment someone is trying to
save a secret rather than at the moment someone is deploying it.

### Configuration

| Variable | Meaning |
|---|---|
| `MCP_CIPHER_KEY_<ID>` | A key. The suffix is its id — `MCP_CIPHER_KEY_V1` gives key `v1` |
| `MCP_CIPHER_ACTIVE_KEY` | Which key seals new values. Optional when only one is configured |
| `MCP_CIPHER_TOKEN` | Shared secret callers send as `x-cipher-token`. Empty disables the check |
| `MCP_CIPHER_ADDRESS` | Listen address. Default `127.0.0.1:9090` |

**Keys come from the environment and nowhere else** — not from a file this repository
tracks, and not from mcp-config. That config server has no authentication and its overrides
reach every client; the panel's Node process already receives the database password because
of it. A key placed there would be handed to all of them, which is exactly what this service
exists to prevent.

The address and the token *are* read from mcp-config, when `CONFIG_SERVER_URL` is set —
they are deployment facts, not secrets. An environment variable still wins over what the
server says, and an unreachable config server is logged rather than fatal: the keys are
already loaded, so an outage there must not stop anyone reading a secret anywhere.

The address defaults to loopback on purpose: `0.0.0.0` would make the permissive case the
one you get by forgetting.

## API

| RPC | Purpose |
|---|---|
| `Encrypt` | Seals under the active key; the reply names the key used |
| `Decrypt` | Opens under the key the value was sealed with |
| `Rewrap` | Re-seals under the active key, for rotation |
| `Keys` | Which key is active, and which can still decrypt |

Health (`grpc.health.v1`) and reflection are registered, so an orchestrator can wait for
it and `grpcurl` works without the proto file to hand. **The health check is exempt from
the token**: a probe is run by an orchestrator rather than a caller, and requiring
credentials would put the token into every compose file that wants to wait for this
service. The cipher methods stay protected.

### The context field

Every value is sealed with a `context` string — `model-api-key`, `ssh-private-key` — bound
into the ciphertext as additional authenticated data. A value sealed for one purpose
cannot be opened as another, **even by a caller holding both**, so one compromised call
site cannot read another's secrets. Decrypting with the wrong context fails exactly as a
wrong key does.

### What a caller learns from a failure

That the value could not be opened, and nothing more. Whether the key id was unknown, the
key was wrong, or the context did not match is precisely what someone probing the service
would want to know, and none of it helps a legitimate caller, who has one thing to do
either way.

## Rotation

Adding a key does not invalidate what the old one sealed:

```bash
export MCP_CIPHER_KEY_V1=...        # keeps decrypting what it sealed
export MCP_CIPHER_KEY_V2=...        # seals everything new
export MCP_CIPHER_ACTIVE_KEY=v2
```

Then move stored values across with `Rewrap`, at whatever pace suits. This is why the ring
exists: with a single key, rotation would mean re-encrypting everything in the moment the
key changed, and anything missed would be unreadable for good.

## Cryptography

AES-GCM. Authenticated, so a value that has been altered fails to open rather than opening
into something else — a silently corrupted API key would be indistinguishable from a wrong
one, and the failure would surface as a puzzling 401 from a model provider.

Stored layout is `[12 byte nonce][ciphertext + 16 byte tag]`: one blob in one column. A
nonce kept in a separate field is a second value that has to stay in step with the first,
and the day it does not, the secret is unrecoverable.

The nonce is random per call and never derived from the plaintext, the key or a counter.
Reusing a nonce under GCM does not merely weaken it — it leaks the key stream and allows
forgery.

## Tests

```bash
go test ./...
```

The server is exercised over a real gRPC connection (`bufconn`) rather than by calling the
methods directly, so the interceptor, the status codes and the generated types are part of
what is tested. The security properties are asserted rather than asserted-in-prose: that a
tampered byte fails authentication, that the context is binding, that a different key does
not open a value, and that 500 seals of identical plaintext produce 500 distinct nonces.

## Layout

```
proto/cipher/v1/    the contract
pkg/pb/cipher/      generated, checked in
internal/cipher/    seal and open one value
internal/keyring/   the keys, and which one is active
internal/server/    gRPC surface and the token check
internal/config/    the environment
cmd/                entry point
```

Regenerate after changing the proto:

```bash
protoc --go_out=. --go_opt=module=mcp-cipher \
       --go-grpc_out=. --go-grpc_opt=module=mcp-cipher \
       proto/cipher/v1/cipher.proto
```

## Callers

`mcp-gateway` stores model API keys through this service. It holds no key of its own: it
sends a value, stores the ciphertext and the returned `key_id`, and asks again to read it
back. Its local AES implementation has been removed, along with the key the config server
used to serve it.

When this service is unreachable the gateway answers `503 CIPHER_UNAVAILABLE` — a
dependency being down, worth retrying — rather than saving a model with no key or failing
in a way that reads like a bad request. Saving a model *without* a key still works, because
that path never asks.
