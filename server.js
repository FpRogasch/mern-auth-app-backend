require("dotenv").config();
// importando módulos necesarios
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");

// Definiendo puerto de conexión
const port = process.env.PORT || 5000;

// inicializando Express
const app = express();

// Middlewares
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(bodyParser.json())

app.use(cors({ 
    origin: ["http://localhost:3000", "https://authz-app.vercel.app"],
    credentials: true
}))


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