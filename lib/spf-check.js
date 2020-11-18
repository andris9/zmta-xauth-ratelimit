'use strict';

const { spf } = require('mailauth/lib/spf');

const spfCheck = async (app, address, session) => {
    // Do not allow bounce messages as we can't validate SPF for these
    if (!address?.address) {
        let err = new Error('Sender address can not be empty');
        err.name = 'SMTPReject';
        err.responseCode = 550;
        throw err;
    }

    let result = await spf({
        sender: address.address,
        ip: session.remoteAddress,
        helo: session.hostNameAppearsAs || session.clientHostname
    });

    app.logger.info(
        'SPF',
        '%s SPFCHECK from=%s ip=%s result=%s resolution=%s',
        session.envelopeId,
        address.address,
        session.remoteAddress,
        result?.status?.result,
        result?.status?.result === 'pass' ? 'PASS' : 'DROP'
    );

    if (['none', 'softfail', 'fail'].includes(result?.status?.result)) {
        // SPF was rejected, not enabled or ended with ~all
        let err = new Error(`Not allowed to send from ${address.address}`);
        err.name = 'SMTPReject';
        err.responseCode = 550;
        throw err;
    }

    if (result?.status?.result !== 'pass') {
        // might be some temporary error?
        let err = new Error(`Can not send from ${address.address}. Try again later.`);
        err.name = 'SMTPReject';
        err.responseCode = 452;
        throw err;
    }

    // allow this message to pass
    return true;
};

module.exports = spfCheck;
