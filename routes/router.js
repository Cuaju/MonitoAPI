const express = require("express");

const { getSysDescr, getProcesses, getHrStorage, getCpuUsage,getUsers} = require("../controllers/controller");
const router = express.Router();

router.get("/system/descr", getSysDescr);     
router.get("/hrstorage",  getHrStorage); 
router.get("/hrswrun", getProcesses);  
router.get("/cpu", getCpuUsage); 
router.get("/users", getUsers); 
module.exports = router;
