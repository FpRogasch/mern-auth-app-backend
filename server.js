require("dotenv").config();
// importando módulos necesarios
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");

const port = process.env.PORT || 5000;

// inicializando Express
const app = express();

app.get("/", (req, res) => {
    res.send("Home Page");
})


mongoose
    .connect(process.env.MONGO_URL)
    .then(() => {
        app.listen(port, () => {
            console.log(`Server running on ${port}`)
        })
    })
    .catch((err) => console.log(err));