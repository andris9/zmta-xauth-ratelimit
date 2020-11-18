'use strict';

const spfCheck = require('./lib/spf-check');
const { checkRateLimit, updateCounters } = require('./lib/process-headers');

module.exports.title = 'X-Auth Rate Limiter';

module.exports.init = function (app, done) {
    // SPF validity is processed immediatelly on MAIL FROM command
    app.addHook('smtp:mail_from', (address, session, next) => {
        spfCheck(app, address, session)
            .then(() => next())
            .catch(err => next(err));
    });

    // Check if rate limit is already reached for this user
    app.addHook('message:headers', (envelope, messageInfo, next) => {
        checkRateLimit(app, envelope, messageInfo)
            .then(() => next())
            .catch(err => next(err));
    });

    // Increment rate limit counters
    app.addHook('message:queue', (envelope, messageInfo, next) => {
        updateCounters(app, envelope, messageInfo)
            .then(() => next())
            .catch(err => next(err));
    });

    done();
};
