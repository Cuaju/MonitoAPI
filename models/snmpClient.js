const snmp = require("net-snmp");

function createSession(target, { version = "2c", community = "public", port = 161, timeout = 2000, retries = 1 } = {}) {
  const opts = { port, retries, timeout, transport: "udp4", version: snmp.Version2c };
  if (String(version) === "1") opts.version = snmp.Version1;
  return snmp.createSession(target, community, opts);
}

function closeSession(session) {
  try { session.close(); } catch { console.log("Failed to close sesion") }
}

function walk(session, baseOid, maxRepetitions = 20) {
  return new Promise((resolve, reject) => {
    const rows = [];
    session.subtree(
      baseOid,
      maxRepetitions,
      (varbinds) => {
        // varbinds is an ARRAY
        for (const vb of varbinds) {
          rows.push(vb);
        }
      },
      (err) => err ? reject(err) : resolve(rows)
    );
  });
}

module.exports = { createSession, closeSession, walk };
