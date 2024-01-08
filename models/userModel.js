const mongoose = require("mongoose");

const userSchema = mongoose.Schema(
    {
        name: { 
            type: String, 
            required: [true, "Please add a name."],
        },
        email: { 
            type: String, 
            required: [true, "Please add an email."],
            unique: true,
            trim: true,
            match: [/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
                "Please enter a valid email",
            ]
        },
        password: { 
            type: String, 
            required: [true, "Please add a password."],
        },
        photo: { 
            type: String, 
            required: [true, "Please add the photo."],
            default: "https://i.ibb.co/4pDNDk1/avatar.png"
        },
        phone: { 
            type: String,
            default: "+56 9 8765 4321"
        },
        bio: { 
            type: String,
            default: "bio..."
        },
        role: { 
            type: String,
            required: true,
            default: "Usuario"
            // Usuario, Ejecutivo, y Admin (Suspended)
        },
        isVerified: { 
            type: Boolean,
            default: false
        },
        userAgent: { 
            type: Array,
            require: true,
            default: []
        },
    }, 
     {
        timestamps: true,
        minimize: false
    }
);

const User = mongoose.model("User", userSchema);

module.exports = User;