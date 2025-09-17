// test-hrStorageType.js
const snmp = require('net-snmp');

const target = process.argv[2] || '192.168.1.79';
const community = process.argv[3] || 'seguro';
const base = '1.3.6.1.2.1.25.2.3.1.2'; // hrStorageType

const session = snmp.createSession(target, community, {
  version: snmp.Version2c, timeout: 2500, retries: 1, transport: 'udp4'
});

function asStr(v) {
  if (v == null) return '';
  if (Buffer.isBuffer(v)) return v.toString();
  if (Array.isArray(v)) return v.join('.');
  return String(v);
}

session.walk(base, 20, (varbinds) => {
  for (const vb of varbinds) {
    console.log(`${vb.oid} = ${vb.type}: ${asStr(vb.value)}`);
  }
}, (err) => {
  if (err) console.error('walk error:', err);
  else console.log('done');
  session.close();
});

