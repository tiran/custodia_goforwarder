# Custodia Forwarder in Go

https://github.com/latchset/custodia

**Proof of Concept**

The Custodia Go Forwarder is a HTTP proxy. It listens on local Unix sockets
and forwards requests to a remote Custodia HTTP server. Requests are
authenticated with a X.509 client certificate. The forwarder fetches
the peer's credential (SO_PEERCRED) and SELinux security label.

## Run example app

```
    $ git submodule update --init
    $ make run_custodia
    $ make init_secrets
    $ make run_goforwarder
    $ make request
```
