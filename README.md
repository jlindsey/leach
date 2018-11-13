Leach
======

**L**et's **E**ncrypt **A**utomated **C**ertificate **H**andler.

Automated, Consul-driven service for LetsEncrypt certificate requests and renewals.

Setup
-----

To bootstrap the tool, a config key needs to be added to Consul's KV store. The `{PREFIX}` in
the list below is customizable with the `CONSUL_PREFIX` env var or flag and by default is `Leach`.

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
    },
    "dns_config": {}
}
```

Where `email` is the address to register with LetsEncrypt, and `ident` is the default CSR Subject
identification info. The `dns_config` object is explained lower down. This will allow the service
to start up and generate a new LetsEncrypt account (storing the info in `{PREFIX}/auth`).

See below for additional configuration options and their defaults. The three JSON keys above are the
minimum to get a working setup.

Once the `{PREFIX}/auth` key is created in Consul (after the first successful authentication), you
should copy this data to a secure backup.

Cert Management
---------------

To request a cert and bring it under management, simply create a new (empty) key under `{PREFIX}/sites`:

```sh
$ curl --request PUT http://$CONSUL_ADDR/v1/kv/$CONSUL_PREFIX/sites/www.example.com
```

This key by itself tells Leach to manage the specified domain's cert with default options: it will request
if it's missing from its storage, and renew it on a schedule.

You can also set a `sites/` key's value to a JSON document that overrides and customizes the options used. Any
options available in the main `{PREFIX}/conf` key are avilable to be overridden here, with the exception of
`email`.

Once requested and acquired, certs and private keys are stored in `{PREFIX}/pki` as `www.example.com-cert.pem`
and `www.example.com-key.pem`. This is to allow easy compatibility with
[Fabio's Cert Stores](https://fabiolb.net/feature/certificate-stores/).

### Revocation

To revoke an issued cert, create a new empty key under `{PREFIX}/revoke`:

```sh
$ curl --request PUT http://$CONSUL_ADDR/v1/kv/$CONSUL_PREFIX/rev/www.example.com
```

This will request a certificate revocation from LE upstream, delete the stored private key and cert keys under
`{PREFIX}/pki`, and then delete the triggering key from `{PREFIX}/rev` that you just created to prevent a loop.
If an entry for this cert still exists under `{PREFIX}/sites`, Leach will attempt to aquire another.

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

    // Configuration for the supported DNS providers used for LE auth checks.
    "dns_config": {
        "default": {
            // See "DNS Providers" section below for specifics.
        }
    },

    // Time in days to wait before requesting a cert renewal. Must be 1 < x < 90.
    // LetsEncrypt docs recommend 60-day renewals.
    "renew": 60,

    // Additional names to request on this cert, making it a SAN cert (sites/ only).
    "extra_names": [],

    // DNS provider to use for this cert instead of the deafult (sites/ only).
    "dns_provider": ""
}
```

### DNS Providers

The following DNS provider backends are included and supported. Pull requests to add more are
welcome.

Multiple providers of a given type are allowed, but their names (the keys for the config dicts)
must be unique. There _must_ be exactly one `default` provider.

#### DigitalOcean

```javascript
{
    "dns_config": {
        "default": {
            // DigitalOcean Provider
            "provider": "digitalocean",

            // DO API token with access to the hosted DNS zone
            "token": *,

            // Name of the zone defined in the DO control panel
            "zone": *
        }
    }
}
```

#### Infoblox

```javascript
{
    "dns_config": {
        "default": {
            // Infoblox Provider
            "provider": "infoblox",

            // Base URL of your Infoblox WAPI endpoint (should include the /wapi/<version> path) 
            "url": *,

            // Username for basic auth
            "username": *,

            // Password for basic auth
            "password": *,

            // DNS view(s) to manage records in
            // (see: https://docs.infoblox.com/display/NAG8/Chapter+18+DNS+Views)
            "views": [*]
        }
    }
}
```

Development
-----------

Leach is written in Go and requires version >=1.11 for Go modules support.

You will need a local Consul instance to develop against, which can be launched with Docker like so:

```sh
$ docker run --name consul -d -p 8500:8500 --rm consul
```

This runs Consul in dev mode and does not persist data to disk, so all data will be lost on
a restart of the service. A convenience script is provided in `scripts/bootstrap_consul.sh`
to preload with some data for testing and development. This script requires `curl` and `envsubst`
to be installed and on your `PATH`.

You should `export LE_STAGING=1` to run against the LetsEncrypt staging environment instead of
production, which does not return trusted certs but has much more generous rate limits.
