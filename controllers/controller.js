const snmp = require("net-snmp");
const { createSession, closeSession, walk } = require("../models/snmpClient");
const OIDS = require("../utils/constants")


const STORAGE_TYPE_NAMES = {
  "1.3.6.1.2.1.25.2.1.1": "other",
  "1.3.6.1.2.1.25.2.1.2": "ram",
  "1.3.6.1.2.1.25.2.1.3": "virtualMemory",
  "1.3.6.1.2.1.25.2.1.4": "fixedDisk",
  "1.3.6.1.2.1.25.2.1.5": "removableDisk",
  "1.3.6.1.2.1.25.2.1.6": "floppyDisk",
  "1.3.6.1.2.1.25.2.1.7": "compactDisc",
  "1.3.6.1.2.1.25.2.1.8": "ramDisk",
  "1.3.6.1.2.1.25.2.1.9": "flashMemory",
  "1.3.6.1.2.1.25.2.1.10": "networkDisk"
};

function bufferToString(v) {
  if (v == null) return '';
  if (Buffer.isBuffer(v)) return v.toString();
  if (Array.isArray(v)) return v.join('.');      // just in case an OID comes as array
  switch (typeof v) {
    case 'string': return v;
    case 'number': return String(v);
    case 'object':
      if ('length' in v && typeof v.length === 'number') {
        try { return Array.from(v).join('.'); } catch { /* fall through */ }
      }
      return String(v);
    default: return String(v);
  }
}


function extractIndex(oid, base) {
  const b = base.endsWith(".") ? base : base + ".";
  if (!oid.startsWith(b)) return null;
  const idx = oid.slice(b.length);   // e.g. "1234"
  const n = Number(idx);
  return Number.isFinite(n) ? n : idx; // some tables have composite indexes; keep string then
}


// GET /api/snmp/hrstorage/type?ip=1.2.3.4&community=public
async function getHrStorageType(req, res) {
  const ip = req.query.ip;
  const community = req.query.community || 'public';
  const version = req.query.version || '2c';
  if (!ip) return res.status(400).json({ error: 'ip is required' });

  const base = String((OIDS && OIDS.hrStorageType) || '');   // ensure string
  if (!base) return res.status(500).json({ error: 'OIDS.hrStorageType is undefined' });

  const session = createSession(ip, { version, community, timeout: 2500, retries: 1 });

  try {
    const varbinds = await walk(session, base);

    const rows = varbinds
      .filter(vb =>
        vb &&
        typeof vb.oid === 'string' &&
        !netSnmp.isVarbindError(vb)
      )
      .map(vb => {
        const index = extractIndex(vb.oid, base);
        return {
          index,
          type: bufferToString(vb.value),  // hrStorageType is an OBJECT IDENTIFIER
        };
      })
      .filter(r => r.index !== null);

    res.json({ target: ip, oid: base, count: rows.length, data: rows });
  } catch (e) {
    res.status(502).json({ error: e?.message || String(e) });
  } finally {
    closeSession(session);
  }
}
// GET /api/snmp/hrstorage/descr?ip=1.2.3.4&community=public
async function getHrStorage(req, res) {
  const ip = req.query.ip;
  const community = req.query.community || "public";
  const version = req.query.version || "2c";
  if (!ip) return res.status(400).json({ error: "ip is required" });

  const session = createSession(ip, { version, community, timeout: 2500, retries: 1 });

  try {
    // Walk the whole hrStorage table once
    const base = OIDS.hrStorageTable; // 1.3.6.1.2.1.25.2.3.1
    const vbs = await walk(session, base, 20);

    // Join by index
    const byIndex = new Map();
    const upsert = (colOid, setter) => {
      const prefix = colOid + ".";
      for (const vb of vbs) {
        if (snmp.isVarbindError(vb) || !vb.oid.startsWith(prefix)) continue;
        const idx = extractIndex(vb.oid, colOid);
        if (idx == null) continue;
        const row = byIndex.get(idx) || { index: idx };
        setter(row, vb);
        byIndex.set(idx, row);
      }
    };

    upsert(OIDS.hrStorageDescr,      (r, vb) => r.descr = vbToString(vb.value));
    upsert(OIDS.hrStorageType,       (r, vb) => {
      const oid = vb.value?.toString(); // net-snmp returns OID object/string
      r.typeOid = oid;
      r.type = STORAGE_TYPE_NAMES[oid] || oid;
      r.isRam = oid === OIDS.hrStorageRamType;
    });
    upsert(OIDS.hrStorageAllocUnits, (r, vb) => r.allocBytes = Number(vb.value));  // bytes per unit
    upsert(OIDS.hrStorageSize,       (r, vb) => r.sizeUnits  = Number(vb.value));  // total units
    upsert(OIDS.hrStorageUsed,       (r, vb) => r.usedUnits  = Number(vb.value));  // used units

    // Compute totals
    const data = [...byIndex.values()]
      .filter(r => Number.isFinite(r.allocBytes) && Number.isFinite(r.sizeUnits) && Number.isFinite(r.usedUnits))
      .map(r => {
        const total = r.allocBytes * r.sizeUnits;
        const used  = r.allocBytes * r.usedUnits;
        const pct   = r.sizeUnits > 0 ? (r.usedUnits / r.sizeUnits) * 100 : 0;
        return {
          index: r.index,
          descr: r.descr || "",
          type: r.type || "",
          typeOid: r.typeOid || "",
          isRam: !!r.isRam,
          allocBytes: r.allocBytes,
          sizeUnits: r.sizeUnits,
          usedUnits: r.usedUnits,
          totalBytes: total,
          usedBytes: used,
          freeBytes: Math.max(total - used, 0),
          usedPct: Number.isFinite(pct) ? +pct.toFixed(2) : null,
          // pretty
          pretty: {
            total: humanBytes(total),
            used:  humanBytes(used),
            free:  humanBytes(Math.max(total - used, 0))
          }
        };
      })
      .sort((a, b) => a.index - b.index);

    res.json({ target: ip, count: data.length, data });
  } catch (e) {
    res.status(502).json({ error: e?.message || String(e) });
  } finally {
    closeSession(session);
  }
}


async function getHrStorageDescr(req, res) {

  const ip = req.query.ip;
  const community = req.query.community || "public";
  const version = req.query.version || "2c";
  
  if (!ip) return res.status(400).json({ error: "ip is required" });

  const session = createSession(ip, { version, community, timeout: 2500, retries: 1 });

  try {
    const base = OIDS.hrStorageDescr;
    const varbinds = await walk(session, base);

    const rows = varbinds
      .filter(vb => !require("net-snmp").isVarbindError(vb))
      .map(vb => ({
        index: extractIndex(vb.oid, base),
        descr: bufferToString(vb.value)
      }));

    res.json({
      target: ip,
      oid: base,
      count: rows.length,
      data: rows
    });
  }catch(e){
    res.status(502).json({ error: e?.message || String(e) });
  } finally {
    closeSession(session);
  }

}

// GET /api/snmp/hrstorage/alloc?ip=1.2.3.4&community=public

async function getHrStorageAlloc(req,res){
 const ip = req.query.ip;
  const community = req.query.community || "public";
  const version = req.query.version || "2c";

  if (!ip) return res.status(400).json({ error: "ip is required" });
  
  const session = createSession(ip, { version, community, timeout: 2500, retries: 1 });
  try {
    const base = OIDS.hrStorageAllocUnits;
    const varbinds = await walk(session, base);
    
    const rows = varbinds
      .filter(vb => !require("net-snmp").isVarbindError(vb))
      .map(vb => ({
        index: extractIndex(vb.oid, base),
        allocUnits: Number(vb.value)
      }));
    res.json({
      target: ip,
      oid: base,
      count: rows.length,
      data: rows
    });
  }catch(e){
    res.status(502).json({ error: e?.message || String(e) });
  } finally {
    closeSession(session);
  }
}

// GET /api/snmp/hrstorage/name?ip=1.2.3.4&community=public
async function getHrStorageSize(req, res){
  const ip = req.query.ip;
  const community = req.query.community || "public";
  const version = req.query.version || "2c";
  
  if (!ip) return res.status(400).json({ error: "ip is required" });
  const session = createSession(ip, { version, community, timeout: 2500, retries: 1 });
  try {
    const base = OIDS.hrStorageSize;
    const varbinds = await walk(session, base);
    
    const rows = varbinds
      .filter(vb => !require("net-snmp").isVarbindError(vb))
      .map(vb => ({
        index: extractIndex(vb.oid, base),
        size: Number(vb.value)
      }));
    res.json({
      target: ip,
      oid: base,
      count: rows.length,
      data: rows
    });
  }catch(e){
    res.status(502).json({ error: e?.message || String(e) });
  } finally {
    closeSession(session);
  }
}

// GET /api/snmp/hrstorage/used?ip=1.2.3.4&community=public

async function getHrStorageUsed(req, res){
  const ip = req.query.ip;
  const community = req.query.community || "public";
  const version = req.query.version || "2c";
  
  if (!ip) return res.status(400).json({ error: "ip is required" });
  const session = createSession(ip, { version, community, timeout: 2500, retries: 1 });
  try {
    const base = OIDS.hrStorageUsed;
    const varbinds = await walk(session, base);
    
    const rows = varbinds
      .filter(vb => !require("net-snmp").isVarbindError(vb))
      .map(vb => ({
        index: extractIndex(vb.oid, base),
        used: Number(vb.value)
      }));
    res.json({
      target: ip,
      oid: base,
      count: rows.length,
      data: rows
    });
  }catch(e){
    res.status(502).json({ error: e?.message || String(e) });
  } finally {
    closeSession(session);
  }
}

// GET /api/snmp/hrstorage/used?ip=1.2.3.4&community=public
async function getHrStorageUsed(req, res){
  const ip = req.query.ip;
  const community = req.query.community || "public";
  const version = req.query.version || "2c";
  
  if (!ip) return res.status(400).json({ error: "ip is required" });
  const session = createSession(ip, { version, community, timeout: 2500, retries: 1 });
  try {
    const base = OIDS.hrStorageUsed;
    const varbinds = await walk(session, base);
    
    const rows = varbinds
      .filter(vb => !require("net-snmp").isVarbindError(vb))
      .map(vb => ({
        index: extractIndex(vb.oid, base),
        used: Number(vb.value)
      }));
    res.json({
      target: ip,
      oid: base,
      count: rows.length,
      data: rows
    });
  }catch(e){
    res.status(502).json({ error: e?.message || String(e) });
  } finally {
    closeSession(session);
  }
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

// GET /api/snmp/system/descr?ip=1.2.3.4&community=public
async function getSysDescr(req, res) {
  const ip = req.query.ip;
  const community = req.query.community || "public";
  const timeout = parseInt(req.query.timeout) || 2500;
  const retries = parseInt(req.query.retries) || 2;
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

//GET /api/snmp/hrswrun/path?ip=1.2.3.4&community=public
async function getHrSWRunPath(req, res) {
  
  const ip = req.query.ip;
  const community = req.query.community || "public";
  const version = req.query.version || "2c";

  if (!ip) return res.status(400).json({ error: "ip is required" });
  
  const session = createSession(ip, { version, community, timeout: 2500, retries: 1 });
  try {
    const base = OIDS.hrSWRunPath;
    const varbinds = await walk(session, base);
    
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
  }catch(e){
    res.status(502).json({ error: e?.message || String(e) });
  } finally {
    closeSession(session);
  }
}


const STATUS_MAP = { 1: "running", 2: "runnable", 3: "notRunnable", 4: "invalid" };

async function getProcesses(req, res) {
  const ip = req.query.ip;
  const community = req.query.community || "public";
  const version = req.query.version || "2c";
  if (!ip) return res.status(400).json({ error: "ip is required" });

  const session = createSession(ip, { version, community, timeout: 2500, retries: 1 });

  try {
    const HR_SW_RUN_BASE = "1.3.6.1.2.1.25.4.2.1"; // table base
    const vbs = await walk(session, HR_SW_RUN_BASE, 20);

    const byIndex = new Map();

    function upsert(colOid, setter) {
      const prefix = colOid + ".";
      for (const vb of vbs) {
        if (snmp.isVarbindError(vb) || !vb.oid.startsWith(prefix)) continue;
        const idx = extractIndex(vb.oid, colOid);
        if (idx == null) continue;
        const row = byIndex.get(idx) || { index: idx };
        setter(row, vb);
        byIndex.set(idx, row);
      }
    }

    upsert(OIDS.hrSWRunName,   (row, vb) => row.name   = vbToString(vb.value));
    upsert(OIDS.hrSWRunPath,   (row, vb) => row.path   = vbToString(vb.value));
    upsert(OIDS.hrSWRunStatus, (row, vb) => {
      const n = Number(vb.value);
      row.status = STATUS_MAP[n] || String(n);
    });

    // Optional: also join perf by the same index (different table root)
    const HR_SW_RUN_PERF_BASE = "1.3.6.1.2.1.25.5.1.1";
    const perf = await walk(session, HR_SW_RUN_PERF_BASE, 20);

    function upsertPerf(colOid, key, transform = (x)=>x) {
      const prefix = colOid + ".";
      for (const vb of perf) {
        if (snmp.isVarbindError(vb) || !vb.oid.startsWith(prefix)) continue;
        const idx = extractIndex(vb.oid, colOid);
        if (idx == null) continue;
        const row = byIndex.get(idx) || { index: idx };
        row[key] = transform(vb.value);
        byIndex.set(idx, row);
      }
    }

    upsertPerf(OIDS.hrSWRunPerfCPU, "cpuTicks",  v => Number(v));
    upsertPerf(OIDS.hrSWRunPerfMem, "memKB",     v => Number(v));

    // build output array (filter out rows with no name if desired)
    const data = [...byIndex.values()]
      .filter(r => r.name)                // keep only real processes
      .sort((a, b) => a.index - b.index); // nice ordering

    res.json({ target: ip, count: data.length, data });
  } catch (e) {
    res.status(502).json({ error: e?.message || String(e) });
  } finally {
    closeSession(session);
  }
}


//GET /api/snmp/hrswrun/status?ip=1.2.3.4&community=public
async function getHrSWRunStatus(req, res) {
  const ip = req.query.ip;
  const community = req.query.community || "public";
  const version = req.query.version || "2c";
  
  if (!ip) return res.status(400).json({ error: "ip is required" });
  const session = createSession(ip, { version, community, timeout: 2500, retries: 1 });
  try {
    const base = OIDS.hrSWRunStatus;
    const varbinds = await walk(session, base);
    
    const rows = varbinds
      .filter(vb => !require("net-snmp").isVarbindError(vb))
      .map(vb => ({
        index: extractIndex(vb.oid, base),
        status: Number(vb.value)
      }));
    res.json({
      target: ip,
      oid: base,
      count: rows.length,
      data: rows
    });
  }catch(e){
    res.status(502).json({ error: e?.message || String(e) });
  } finally {
    closeSession(session);
  }
}

//GET /api/snmp/hrswrun/perfcpu?ip=1.2.3.4&community=public
async function getHrSWRunPerfCPU(req, res) {
  const ip = req.query.ip;
  const community = req.query.community || "public";
  const version = req.query.version || "2c";
  
  if (!ip) return res.status(400).json({ error: "ip is required" });
  const session = createSession(ip, { version, community, timeout: 2500, retries: 1 });
  try {
    const base = OIDS.hrSWRunPerfCPU;
    const varbinds = await walk(session, base);
    
    const rows = varbinds
      .filter(vb => !require("net-snmp").isVarbindError(vb))
      .map(vb => ({
        index: extractIndex(vb.oid, base),
        cpu: Number(vb.value)
      }));
    res.json({
      target: ip,
      oid: base,
      count: rows.length,
      data: rows
    });
  }catch(e){
    res.status(502).json({ error: e?.message || String(e) });
  } finally {
    closeSession(session);
  }
}

//GET /api/snmp/hrswrun/perfmem?ip=1.2.3.4&community=public
async function getHrSWRunPerfMem(req, res) {
  const ip = req.query.ip;
  const community = req.query.community || "public";
  const version = req.query.version || "2c";
  
  if (!ip) return res.status(400).json({ error: "ip is required" });
  const session = createSession(ip, { version, community, timeout: 2500, retries: 1 });
  try {
    const base = OIDS.hrSWRunPerfMem;
    const varbinds = await walk(session, base);
    
    const rows = varbinds
      .filter(vb => !require("net-snmp").isVarbindError(vb))
      .map(vb => ({
        index: extractIndex(vb.oid, base),
        mem: Number(vb.value)
      }));
    res.json({
      target: ip,
      oid: base,
      count: rows.length,
      data: rows
    });
  }catch(e){
    res.status(502).json({ error: e?.message || String(e) });
  } finally {
    closeSession(session);
  }
}

function vbToString(val) {
  if (Buffer.isBuffer(val)) return val.toString("utf8").replace(/\u0000/g, "");
  return String(val ?? "");
}

function humanBytes(n) {
  const units = ["B","KB","MB","GB","TB","PB"];
  let i = 0, x = Number(n);
  while (x >= 1024 && i < units.length-1) { x /= 1024; i++; }
  return `${x.toFixed(x < 10 ? 2 : 1)} ${units[i]}`;
}








module.exports = { getSysDescr, getHrStorage, getHrSWRunName, getHrStorageType, getHrStorageDescr, getHrStorageAlloc, getHrStorageSize, getHrStorageUsed, getHrSWRunPath, getHrSWRunStatus, getHrSWRunPerfCPU, getHrSWRunPerfMem, getProcesses };