// Runtime secrets arrive only on stdin; never export a Newman environment/report.
const fs = require('node:fs');
const path = require('node:path');
const newman = require('newman');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', () => {
  const config = JSON.parse(input);
  const samples = {};
  const secrets = [config.password, config.expired_token].filter(Boolean);
  const ids = new Map();
  function syntheticId(value) {
    if (!ids.has(value)) ids.set(value, '00000000-0000-4000-8000-' + String(ids.size + 1).padStart(12, '0'));
    return ids.get(value);
  }
  function sanitize(value, key = '') {
    if (Array.isArray(value)) return value.map(item => sanitize(item, key));
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v]) => [k,sanitize(v,k)]));
    if (typeof value !== 'string') return value;
    if (key !== 'token_type' && /token|password|secret|signature|hmac/i.test(key)) return '';
    if (key === 'username') return 'api_example';
    if (key === 'request_id') return 'example-request-id';
    if (/^Personal de /.test(value)) return 'Personal de api_example';
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value) && key !== 'cpe_name_id') return syntheticId(value);
    if (/^\d{4}-\d\d-\d\dT/.test(value)) return key === 'expected_updated_at' ? '2026-11-13T12:00:00Z' : '2026-11-13T12:00:00.000001Z';
    for (const secret of secrets) value = value.split(secret).join('');
    return value;
  }
  const environment = { values: Object.entries(config).filter(([key]) => !['output','installation'].includes(key)).map(([key,value]) => ({key,value:String(value),enabled:true})) };
  const run = newman.run({
    collection: path.join(__dirname, 'VulnTrack-V2.postman_collection.json'),
    environment, reporters: [], delayRequest: 80, timeoutRequest: 20000,
    timeoutScript: 5000, bail: true
  }, (err, summary) => {
    if (err) { process.stderr.write('Newman failed to run\n'); process.exitCode=1; return; }
    const failures = summary.run.failures.map(f => ({name:f.source?.name || 'runtime',type:f.error?.name || 'failure',test:f.error?.test || '',message: sanitize(f.error?.message || '')}));
    const report = {installation: config.installation, stats: summary.run.stats, failures, samples};
    if(config.output) fs.writeFileSync(config.output, JSON.stringify(report,null,2)+'\n',{mode:0o600});
    process.stdout.write(JSON.stringify({installation:config.installation,stats:summary.run.stats,failures},null,2)+'\n');
    process.exitCode = failures.length ? 1 : 0;
  });
  run.on('request', (err,args) => {
    if(err || !args.response) return;
    try { samples[args.item.name] = {method:args.request.method,status:args.response.code,body:sanitize(args.response.json())}; }
    catch { samples[args.item.name] = {method:args.request.method,status:args.response.code,body:'non-JSON'}; }
  });
});
