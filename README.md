Porter
======

Automated, Consul-driven service for LetsEncrypt certificate requests and renewals.

Setup
-----

To bootstrap the tool, a config key needs to be added to Consul's KV store. The `{PREFIX}` in
the list below is customizable with the `CONSUL_PREFIX` env var or flag and by default is `porter`.

`{PREFIX}/conf` must be a JSON doc like so:

```javascript
{
    "email": "test@example.com",
    "ident": {
        "country": ["US"],
        "province": ["Virginia"],
        "locality": ["Arlington"],
        "organization": ["My Org"],
        "organizational_unit": ["My Dept"]
    }
}
```

Where `email` is the address to register with LetsEncrypt, and `ident` is the default CSR Subject
identification info. This will allow the service to start up and generate a new LetsEncrypt
account (storing the info in `{PREFIX}/auth`).

See below for additional configuration options and their defaults. The two JSON keys above are the
minimum to get a working setup.

Cert Management
---------------

To request a cert and bring it under management, simply create a new (empty) key under `{PREFIX}/sites`:

```sh
$ curl --request PUT http://$CONSUL_ADDR/v1/kv/$CONSUL_PREFIX/sites/www.example.com
```

This key by itself tells Porter to manage the specified domain's cert with default options: it will request
if it's missing from its storage, and renew it on a schedule.

You can also set a `sites/` key's value to a JSON document that overrides and customizes the options used. Any
options available in the main `{PREFIX}/conf` key are avilable to be overridden here, with the exception of
`email`.

Once requested and acquired, certs and private keys are stored in `{PREFIX}/pki` as `www.example.com-cert.pem`
and `www.example.com-key.pem`. This is to allow easy compatibility with
[Fabio's Cert Stores](https://fabiolb.net/feature/certificate-stores/).

### Revocation

To revoke an issued cert, create a new empty key under `{PREFIX}/rev`:

```sh
$ curl --request PUT http://$CONSUL_ADDR/v1/kv/$CONSUL_PREFIX/rev/www.example.com
```

This will request a certificate revocation from LE upstream, delete the stored private key and cert keys under
`{PREFIX}/pki`, and then delete the triggering key from `{PREFIX}/rev` that you just created to prevent a loop.
If an entry for this cert still exists under `{PREFIX}/sites`, Porter will attempt to aquire another.

If you want to go scorched-earth, you can set the `{PREFIX}/rev` to a JSON document of `{"purge": true}`:

```sh
$ curl --request PUT --data '{"purge": true}' http://$CONSUL_ADDR/v1/kv/$CONSUL_PREFIX/rev/www.example.com
```

This will do everything as described above, but will _also_ delete the entry under `{PREFIX}/sites` and revoke
the cached LE authorization for the domain.

Configuration
-------------

The following configuration variables are available to be set in the `{PREFIX}/conf` key and overridden
in `sites/` unless otherwise noted. Defaults are shown below. Options with a `*` are required and
have no default.

```javascript
{
    // Email address to register with LE
    "email": *,

    // CSR Subject values for requesting certs. All keys below are required and must be arrays.
    "ident": {
        "country": [*],
        "province": [*],
        "locality": [*],
        "organization": [*],
        "organizational_unit": [*]
    },

    // Time in days to wait before requesting a cert renewal. Must be 1 < x < 90.
    "renew": 60,

    // Additional names to request on this cert, making it a SAN cert (sites/ only).
    "extra_names": []
}
```