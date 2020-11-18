'use strict';

const crypto = require('crypto');

const sha1 = str => crypto.createHash('sha1').update(str).digest('hex').toLowerCase();

// A crux to caluclate seconds until the end of current minute/date (in UTC)
const secondsUntilPeriodEnd = type => {
    let ttlMs = 0;
    switch (type) {
        case 'minute':
            ttlMs = new Date(new Date().toISOString().substr(0, 16) + ':00.000Z').getTime() + 60 * 1000 - Date.now();
            break;
        case 'day':
        default:
            ttlMs = new Date(new Date().toISOString().substr(0, 11) + '00:00:00.000Z').getTime() + 24 * 3600 * 1000 - Date.now();
            break;
    }
    return Math.ceil(ttlMs / 1000);
};

// rate limit message based on X-AuthUser header
const checkRateLimit = async (app, envelope) => {
    // resolve authenticated user
    let authUser = envelope.headers.getFirst('X-AuthUser');
    authUser = authUser.trim().toLowerCase();

    if (!authUser) {
        // do nothing, message is queued as we were not able to determine user rate limits
        return false;
    }

    // store to be used by updateCounters
    envelope.authUser = authUser;

    // load rate limit options from DB
    let res = await app.db.senderDb.collection('accountdata').findOne(
        {
            account: authUser
        },
        {
            projection: {
                'ratelimits.minute': true,
                'ratelimits.day': true
            }
        }
    );

    // merge default and db results
    let ratelimits = Object.assign({}, app.config.ratelimits || {}, res?.ratelimits || {});

    // function to check if rate limits for time perion are reached or not
    const rlCheck = async (type, allowed) => {
        let res = await app.db.redis
            .multi()
            .get(`ratelilimit:${sha1(authUser)}:${type}`)
            .ttl(`ratelilimit:${sha1(authUser)}:${type}`)
            .exec();
        if (res?.[0][0]) {
            throw res?.[0][1];
        }
        let counter = Number(res?.[0][1]) || 0;
        let ttl = Number(res?.[1][1]) || 0;

        if (ttl === -2) {
            // key not found, ignore for now
            return;
        }

        app.logger.info(
            'RATELIMIT',
            '%s RLCHECK type=%s counter=%s allowed=%s ttl=%s resolution=%s',
            envelope.id,
            type,
            counter,
            allowed,
            ttl,
            counter < allowed ? 'PASS' : 'DROP'
        );

        if (counter >= allowed) {
            // too many messages per minute
            let err = new Error(`Too many messages sent. Try again later`);
            err.name = 'SMTPReject';
            err.responseCode = 452;
            throw err;
        }
    };

    // check rate limits
    for (let type of ['minute', 'day']) {
        await rlCheck(type, ratelimits[type]);
    }

    // seems ok
    return true;
};

const updateCounters = async (app, envelope) => {
    if (!envelope.authUser) {
        // nothing to do here
        return false;
    }

    let authUser = envelope.authUser;

    let updateCounter = async type => {
        await app.db.redis
            .multi()
            .incrby(`ratelilimit:${sha1(authUser)}:${type}`, envelope.to.length)
            .expire(`ratelilimit:${sha1(authUser)}:${type}`, secondsUntilPeriodEnd(type) || 1) // default to 1 if there is 0 seconds left, otherwise the timer is not released
            .exec();
    };

    for (let type of ['minute', 'day']) {
        await updateCounter(type);
    }
};

module.exports = { checkRateLimit, updateCounters };
