const { workerData, parentPort } = require('node:worker_threads');
const _ = require('lodash');
const moment = require('moment');
const nodemailer = require('nodemailer');
const MailComposer = require('nodemailer/lib/mail-composer');
const fetch = require('node-fetch');
const https = require('https');

const sendReports = async (reports) => {
  const sendHTTP = async (url, policyDomain, report) => {
    try {
      if (workerData?.config?.http?.url) {
        const originalURL = url;
        url = workerData?.config?.http?.url;
        console.log('Debug mode: ' + originalURL + ' -> ' + url);
      }
      if (!url)
        return;
      const results = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/tlsrpt+json'
        },
        body: JSON.stringify(report),
        agent: new https.Agent({
          rejectUnauthorized: workerData?.config?.http?.tls?.rejectUnauthorized ?? false
        })
      });
      if (results?.status > 299)
        throw 'Status: ' + results?.status + ' (' + results.statusText + ')';
    } catch (err) {
      console.log('Error (policy-domain: ' + policyDomain + ') (https): ' + err);
    }
  };

  const sendSMTP = async (to, policyDomain, report) => {
    try {
      if (workerData?.config?.smtp?.to) {
        const originalTo = to;
        to = workerData?.config?.smtp?.to;
        console.log('Debug mode: ' + originalTo + ' -> ' + to);
      }
      if (!to)
        return;
      if (!workerData?.config?.smtp?.host)
        throw 'No SMTP server configured';

      const transporter = nodemailer.createTransport({
        host: workerData?.config?.smtp?.host,
        port: workerData?.config?.smtp?.port ?? 587,
        tls: {
          ...workerData?.config?.smtp?.tls ?? {},
          rejectUnauthorized: workerData?.config?.smtp?.tls?.rejectUnauthorized ?? false
        },
        auth: workerData?.config?.smtp?.auth
      });
      const mailOptions = {
        from: workerData?.config?.smtp?.from,
        to: to,
        subject: [
          'Report Domain: ' + policyDomain,
          'Submitter: ' + workerData?.config?.submitter,
          'Report-ID: <' + workerData?.reportId + '@' + policyDomain + '>'
        ].join(' '),
        headers: {
          'X-Mailer': 'Halon',
          'TLS-Report-Domain': policyDomain,
          'TLS-Report-Submitter': workerData?.config?.submitter
        },
        text: 'This is an aggregate TLS report from ' + workerData?.config?.submitter,
        attachments: [
          {
            filename: [workerData?.config?.submitter, policyDomain, workerData?.startDate / 1000, workerData?.endDate / 1000].join('!') + '.json',
            content: Buffer.from(JSON.stringify(report, undefined, 2)).toString('base64'),
            encoding: 'base64',
            contentType: 'application/tlsrpt+json'
          }
        ]
      };
      const mime = new MailComposer(mailOptions).compile();
      mime.setHeader('Content-Type', 'multipart/report; report-type="tlsrpt";');
      await transporter.sendMail({
        from: workerData?.config?.smtp?.from,
        to: to,
        raw: await mime.build()
      });
    } catch (err) {
      console.log('Error (policy-domain: ' + policyDomain + ') (smtp): ' + err);
    }
  };

  await Promise.all(reports.map(async report => {
    const policyDomain = _.get(report, 'policy-domain');
    const policies = (_.get(report, 'policy-type') ?? []).map((policy) => {
      const policyType = Object.keys(policy)[0];
      let policyString = '';
      let summary = {
        'total-successful-session-count': 0,
        'total-failure-session-count': 0
      };
      let failureDetails = [];
      (_.get(policy[policyType], 'result-type') ?? []).map(result => {
        const resultType = Object.keys(result)[0];
        if (resultType === 'success') {
          summary['total-successful-session-count'] += _.get(result[resultType], 'count') ?? 0;
        } else {
          summary['total-failure-session-count'] += _.get(result[resultType], 'count') ?? 0;
        }
        (_.get(result[resultType], 'details') ?? []).forEach(details => {
          policyString = _.get(details, 'policy-string');
          if (resultType !== 'success') {
            failureDetails.push({
              'result-type': resultType,
              'sending-mta-ip': _.get(details, 'details.sending-mta-ip'),
              'receiving-mx-hostname': _.get(details, 'receiving-mx-hostname'),
              'receiving-mx-helo': _.get(details, 'receiving-mx-helo'),
              'receiving-ip': _.get(details, 'receiving-mta-ip'),
              'failed-session-count': _.get(details, 'count') ?? 0
            });
          }
        });
      });

      // Do not use mx-host for now
      // let mxHost = undefined;
      // if (policyType == 'sts' && Array.isArray(policyString)) {
      //   policyString.forEach(p => {
      //     const mx = /^mx:\s?(.+)$/.exec(p);
      //     if (mx && mx.length == 2)
      //       mxHost = mx[1];
      //   });
      // }
      return {
        'policy': {
          'policy-type': policyType,
          'policy-string': policyString,
          'policy-domain': policyDomain,
          // 'mx-host': mxHost
        },
        'summary': summary,
        'failure-details': failureDetails
      }
    });

    const sendReport = {
      'organization-name': _.get(workerData?.config, 'organization-name'),
      'date-range': {
        'start-datetime': moment.unix(workerData?.startDate / 1000).format('YYYY-MM-DDTHH:mm:ss[Z]'),
        'end-datetime': moment.unix(workerData?.endDate / 1000).format('YYYY-MM-DDTHH:mm:ss[Z]')
      },
      'contact-info': _.get(workerData?.config, 'contact-info'),
      'report-id': workerData?.reportId,
      'policies': policies
    };

    await report.rua.map(async r => {
        if (r.scheme === 'mailto')
          await sendSMTP(r.sendto, policyDomain, sendReport);
        else if (r.scheme === 'https')
          await sendHTTP(r.sendto, policyDomain, sendReport);
        else
          console.log('Unsupported scheme ' + report.scheme);
    });

    parentPort.postMessage({ id: workerData.id, data: [] });
  }));
};

parentPort.on('message', message => {
  if (message === 'close')
    parentPort.close();
  else
    sendReports(message.data);
});