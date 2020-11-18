# zmta-xauth-ratelimit

Example SPF check and rate limit plugin for Zone-MTA.

## Setup

Add this as a dependency for your ZoneMTA app

```
npm installzmta-xauth-ratelimit --save
```

### Configuration

Assuming you are using configuration format from [zone-mta-template](https://github.com/zone-eu/zone-mta-template) create config file `plugins/zmta-xauth-ratelimit.toml`

```toml
# plugins/zmta-xauth-ratelimit.toml
["modules/zmta-xauth-ratelimit"]
enabled=["receiver"]

["modules/zmta-xauth-ratelimit".ratelimits]
minute = 60
day = 1000
```
