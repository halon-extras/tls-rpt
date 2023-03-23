const { workerData, parentPort } = require('node:worker_threads');
const { Resolver } = require('node:dns');
const resolver = new Resolver({
  timeout: 1 * 1000,
  tries: 1
});

const resolvePolicyDomain = async (domainlist) => {
  try {
    const lookupTLSRPT = async (policyDomain) => {
      const hostname = `_smtp._tls.${policyDomain}`;
      const txtrecords = await new Promise((resolve, reject) => {
        resolver.resolveTxt(hostname, (err, record) => {
          return resolve(record);
        });
      });
      let tlsrptv1 = '';
      (txtrecords ?? []).forEach((record) => {
        const s = record.join('');
        if (s?.startsWith('v=TLSRPTv1;'))
          tlsrptv1 = s;
      });
      return tlsrptv1;
    };

    const results = [];
    await Promise.all(domainlist.map(i => {
      return new Promise(async (resolve, reject) => {
        const ruaRaw = (await lookupTLSRPT(i['policy-domain']))
          .split(';')
          .filter(r => /^rua=/.exec(r.trim()))
          .join('')
          .trim()
          .replace(/^rua=/, '');
        const ruaList = [];
        if (ruaRaw) {
          ruaRaw.split(',').forEach(r => {
            const match = /((https?(?=:)|mailto(?=:))[^\s]+)/.exec(r);
            if (match.length == 3) {
              ruaList.push({
                sendto: match[1].replace(/^mailto:/, ''),
                scheme: match[2] 
              });
            }
          });
        }
        if (ruaList.length > 0)
          results.push({ ...i, rua: ruaList });
        return resolve();
      });
    }));
    parentPort.postMessage({ id: workerData.id, data: results });
  } catch (err) {
    console.log(err);
    parentPort.postMessage({ id: workerData.id, data: [] });
  }
}

parentPort.on('message', message => {
  if (message === 'close')
    parentPort.close();
  else
    resolvePolicyDomain(message?.data ?? []);
});
