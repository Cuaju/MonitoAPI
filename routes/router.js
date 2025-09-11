const express = require("express");
const { getHrSWRunName, getSysDescr } = require("../controllers/controller");
const router = express.Router();

router.get("/system/descr", getSysDescr);     // new probe
router.get("/hrswrun/name", getHrSWRunName);  // your original
module.exports = router;
