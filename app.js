const express = require('express')
const routes = require('./routes/router')
const cors = require ('cors')
const app = express();

app.use(cors());

app.get("/healthz", (_, res) => res.send("ok"));
app.use("/api/snmp", routes);
app.use(express.json());


module.exports = app;

if (require.main === module){
    const port = 6969
    app.listen(port, () =>{
        console.log(`SERVIDOR SNMP ejecutandose en http://localhost:${port}/api/monito`)
    })
}

