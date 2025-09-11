const snmp = require("net-snmp");
const { createSession, closeSession, walk } = require("../models/snmpClient");
const OIDS = require("../utils/constants")

function bufferToString(v) {
  if (Buffer.isBuffer(v)) return v.toString();
  return String(v);
}

function extractIndex(oid, baseOid) {
  const baseLen = baseOid.split(".").length;
  const parts = oid.split(".").slice(baseLen); // usually a single integer
  return parts.join("."); // keep as string; caller can Number() if needed
}

// GET /api/snmp/hrswrun/name?ip=1.2.3.4&community=public
async function getHrSWRunName(req, res) {
  const ip = req.query.ip;
  const community = req.query.community || "public";
  const version = req.query.version || "2c";

  if (!ip) return res.status(400).json({ error: "ip is required" });

  const session = createSession(ip, { version, community, timeout: 2500, retries: 1 });

  try {
    const base = OIDS.hrSWRunName;
    const varbinds = await walk(session, base);

    // Map to { index, name }
    const rows = varbinds
      .filter(vb => !require("net-snmp").isVarbindError(vb))
      .map(vb => ({
        index: extractIndex(vb.oid, base),
        name: bufferToString(vb.value)
      }));

    res.json({
      target: ip,
      oid: base,
      count: rows.length,
      data: rows
    });
  } catch (e) {
    res.status(502).json({ error: e?.message || String(e) });
  } finally {
    closeSession(session);
  }
}

// GET /api/snmp/system/descr?ip=...&community=public&timeout=5000&retries=2
async function getSysDescr(req, res) {
  const ip = req.query.ip;
  const community = req.query.community || "public";
  const timeout = Number(req.query.timeout || 3000);
  const retries = Number(req.query.retries || 1);
  if (!ip) return res.status(400).json({ error: "ip is required" });

  const session = createSession(ip, { version: "2c", community, timeout, retries });
  try {
    const OID = "1.3.6.1.2.1.1.1.0"; // sysDescr.0
    const vb = await new Promise((resolve, reject) => {
      session.get([OID], (err, vbs) => err ? reject(err) : resolve(vbs[0]));
    });
    if (snmp.isVarbindError(vb)) {
      return res.status(502).json({ error: snmp.varbindError(vb) });
    }
    res.json({ target: ip, oid: OID, value: Buffer.isBuffer(vb.value) ? vb.value.toString() : vb.value });
  } catch (e) {
    res.status(502).json({ error: e?.message || String(e) });
  } finally {
    closeSession(session);
  }
}


module.exports = { getSysDescr, getHrSWRunName }; // keep your existing export too