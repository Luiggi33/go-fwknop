# go-fwknop
A fwknop-inspired Single Packet Authorization written in Go

## What is this?
I was recently confronted with the project fwknop by mrash (https://github.com/mrash/fwknop/) and as I wanted to improve my GoLang skills, I started working on (re)creating something that is inspired by fwknops SPA.

## Should I use this?
Right now, you probably shouldn't use it in anything production worthy. Any test usage and subsequent bug reporting is appreciated!

## Sending a knock
`cmd/client` builds and sends a single SPA packet. Build it with `go build ./cmd/client`, or just run it directly:

```
KNOCK_KEY="$(cat alice.key)" go run ./cmd/client \
    -server knock.example.com -knock-port 62201 -user alice -proto tcp -port 22
```

`-proto`/`-port` say which rule you want opened and have to match a rule in the daemon's config; they default to `tcp`/`22`.

The AES key is read from `$KNOCK_KEY` or from `-key-file`, both base64 like in the config. There is deliberately no `-key` flag, since anything passed on the command line ends up in your shell history and in `ps` output.

The client figures out its own source IP from the socket it's about to send on, which is the address the daemon needs to see in the payload. That is the right answer unless you're behind NAT, in which case pass the public address the daemon sees with `-source-ip`. IPv4 and IPv6 both work and the family is picked automatically from whatever `-server` resolves to.

## TODO
- [x] pass source ip in package and validate it against config
- [x] add cmd/client to create such spa packets
- [x] rethink the throwing out of packet digests
- [ ] add pf firewall
- [ ] make it a service/daemon
- [x] eval to go back to HMAC and AES
- [x] FULLY support IPv6