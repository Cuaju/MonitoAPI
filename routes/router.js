const express = require("express");

const { getSysDescr, getHrSWRunName, getProcesses, getHrStorage, getHrStorageType, getHrStorageDescr, getHrStorageAlloc, getHrStorageSize, getHrStorageUsed, getHrSWRunPath, getHrSWRunStatus, getHrSWRunPerfCPU, getHrSWRunPerfMem } = require("../controllers/controller");
const router = express.Router();

router.get("/system/descr", getSysDescr);     
router.get("/hrstorage",  getHrStorage); 
router.get("/hrswrun", getProcesses);  


module.exports = router;
