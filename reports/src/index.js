const fs = require('fs');
const path = require('path');
const YAML = require('yaml');
const moment = require('moment');
const { Client } = require('@elastic/elasticsearch');
const _ = require('lodash');
const { Worker } = require('node:worker_threads');
const { v4: uuidv4 } = require('uuid');

class tlsrpt {
  config = {};
  client = null;

  constructor() {
    try {
      const fileContents = fs.readFileSync(path.join(__dirname, '../', 'tlsrpt.yaml'), 'utf8');
      this.config = YAML.parse(fileContents);

      if (this.config.elasticsearch) {
        this.client = new Client({
          nodes: this.config.elasticsearch.nodes?.map(i => {
            return { url: new URL(i.url) };
          }),
          auth: this.config.elasticsearch.auth,
          tls: this.config.elasticsearch.tls
        });
      }
      this.config.workers = this.config.workers ?? 1;
    } catch (err) {
      console.log(err);
    }
  }

  async search(startDate, endDate, after = undefined) {
    if (!this.client)
      throw 'Elasticsearch client failed to initialize';
    const searchAggs = {
      aggs: {
        'tlsrpt': {
          composite: {
            size: 1000,
            sources: {
              'policy-domain': {
                terms: {
                  field: 'policy-domain.keyword'
                }
              }
            },
            after: after
          },
          aggs: {
            'policy-type': {
              terms: {
                field: 'policy-type.keyword'
              },
              aggs: {
                'result-type': {
                  terms: {
                    field: 'result-type.keyword'
                  },
                  aggs: {
                    'details': {
                      multi_terms: {
                        terms: [
                          {
                            field: 'sending-mta-ip.keyword'
                          },
                          {
                            field: 'receiving-ip.keyword'
                          }
                        ]
                      },
                      aggs: {
                        'additional_details': {
                          top_hits: {
                            '_source': ['receiving-mx-hostname', 'policy-string', 'receiving-mx-helo'],
                            size: 10
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    };
    return await this.client.search({
      index: this.config.index,
      size: 0,
      query: {
        range: {
          timestamp: {
            gte: startDate,
            lte: endDate
          }
        }
      },
      ...searchAggs
    });
  }

  format(bucket) {
    return {
      'policy-domain': _.get(bucket, 'key.policy-domain'),
      'count': _.get(bucket, 'doc_count') ?? 0,
      'policy-type': _.get(bucket, 'policy-type')?.buckets?.map(pt => {
        return {
          [_.get(pt, 'key')]: {
            'count': _.get(pt, 'doc_count'),
            'result-type': _.get(pt, 'result-type')?.buckets?.map(rt => {
              return {
                [_.get(rt, 'key')]: {
                  'count': _.get(rt, 'doc_count'),
                  'details': _.get(rt, 'details')?.buckets?.map(ds => {
                    const sendingMta = _.get(ds, 'key')[0];
                    const receivingMta = _.get(ds, 'key')[1];
                    // additional details from top_hits
                    const additional_details = _.get(ds, 'additional_details.hits.hits');
                    return {
                      'count': _.get(ds, 'doc_count'),
                      'sending-mta-ip': sendingMta,
                      'receiving-mta-ip': receivingMta,
                      'receiving-mx-hostname': _.get(additional_details[0] ?? {}, '_source.receiving-mx-hostname'),
                      'receiving-mx-helo': _.get(additional_details[0] ?? {}, '_source.receiving-mx-helo'),
                      'policy-string': _.get(additional_details[0] ?? {}, '_source.policy-string')
                    };
                  })
                }
              };
            })
          }
        };
      })
    };
  }

  async workers(type, data, opts = {}) {
    const results = [];
    const workers = [];
    for(let i = 1; i <= this.config.workers; i++) {
      const id = uuidv4();
      workers[id] = {};
      workers[id].worker = new Worker(path.join(__dirname, type + '.js'), {
        workerData: { ...opts, id: id, data: [] }
      });
      workers[id].worker.on('message', (message) => {
        console.log(type, message);
        results.push(...message.data);
        workers[id].busy = false;
      });
    }

    const feedWorkers = async () => {
      const workersIdle = [];
      Object.keys(workers).forEach(id => {
        if (!workers[id].busy)
          workersIdle.push(id);
      });
      if (data.length < 1 && workersIdle.length === this.config.workers)
        return true;
      if (data.length > 0 && workersIdle.length > 0) {
        workers[workersIdle[0]].busy = true;
        workers[workersIdle[0]].worker.postMessage({ data: data.splice(0, 5) });
      }
      await new Promise(async (resolve, reject) => {
        setTimeout(resolve, 20);
      });
      await feedWorkers();
    };
    await feedWorkers();

    Object.keys(workers).forEach(id => {
      workers[id].worker.postMessage('close');
    });
    return results;
  }

  async exec() {
    try {
      const reportId = uuidv4();
      const t_start = moment().unix();
      const startDate = moment().subtract(1, 'days').startOf('day').unix() * 1000;
      const endDate = moment().subtract(1, 'days').endOf('day').unix() * 1000;
      console.log('TLS-RPT: ' + reportId);

      let queue = [];
      let after = undefined;
      let countPolicyDomains = 0;
      while(true) {
        const { aggregations } = await this.search(startDate, endDate, after);
        if (!aggregations?.tlsrpt)
          throw 'No data returned';
        if ((aggregations.tlsrpt?.buckets ?? []).length < 1)
          break;
        const policyDomains = aggregations.tlsrpt?.buckets.map(bucket => {
          return this.format(bucket);
        });
        countPolicyDomains += policyDomains.length;
        queue = [...queue, ...(await this.workers('resolve', policyDomains))];
        after = _.get(aggregations, 'tlsrpt.after_key');
      }
      console.log('# Done (in ' + (moment().unix() - t_start )+ 's)');
      console.log('# Policy domains: ' + countPolicyDomains + ', Queue: ' + queue.length);

      await this.workers('send', queue, {
        reportId: reportId,
        config: this.config,
        startDate: startDate,
        endDate: endDate
      });
    } catch (err) {
      console.log(err);
    }
  }
}

const reporter = new tlsrpt();
reporter.exec();
