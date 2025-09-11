const express = require("express");
const { getHrSWRunName, getSysDescr } = require("../controllers/controller");
const router = express.Router();

router.get("/system/descr", getSysDescr);     
router.get("/hrswrun/name", getHrSWRunName);  

module.exports = router;
