const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const bcrypt = require("bcryptjs");
const { generateToken } = require("../utils");
var parser = require("ua-parser-js");
const jwt = require("jsonwebtoken");

// Register User
const registerUser = asyncHandler (async (req, res) => {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
        res.status(400)
        throw new Error("Please fill in all the require fields.")
    }

    if (password.length < 6) {
        res.status(400)
        throw new Error("Password must be up to 6 characters.")
    }

    // check if user exist
    const userExists = await User.findOne({ email })

    if (userExists) {
        res.status(400)
        throw new Error("Email already in use.")
    }

    // Get user Agent
    const ua = parser(req.headers['user-agent']);
    const userAgent = [ua.ua]

    // Create new user
    const user = await User.create({
        name,
        email,
        password,
        userAgent,
    });

    // Generate Token
    const token = generateToken(user._id);

    // Send HTTP-only cookie
    res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1 day
        sameSite: "none",
        secure: true,
    })

    if (user) {
        const { _id, name, email, phone, bio, photo, role, isVerified } = user;
        
        res.status(201).json({
            _id,
            name, 
            email, 
            phone, 
            bio,
            photo,
            role,
            isVerified,
            token
        });
    } else {
        res.status(400)
        throw new Error("Ivalid user data.");
    }

}); 

// Login User
const loginUser = asyncHandler (async (req, res) => {

    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
        res.status(400);
        throw new Error
    }

    const user = await User.findOne({ email });

    if (!user) {
        res.status(404);
        throw new Error("User not found, please signup");
    }

    const passwordIsCorrect = await bcrypt.compare(password, user.password);

    if (!passwordIsCorrect) {
        res.status(400);
        throw new Error("Invalid email or password");
    }

    // Trigger 2FA for unkwon UserAgent

    // Generate Token
    const token = generateToken(user._id);

    if (user && passwordIsCorrect) {
        // Send Http-only cookie
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // 1 day
            sameSite: "none",
            secure: true,
        });

        const { _id, name, email, phone, bio, photo, role, isVerified } = user;
        res.status(200).json({
            _id,
            name,
            email,
            phone,
            bio,
            photo,
            role,
            isVerified,
            token,
        })

    } else {
        res.status(500);
        throw new Error("Something went wrong, please try again.");
    }

})

// Logout User
const logoutUser = asyncHandler (async (req, res) => {
    // Send Http-only cookie
    res.cookie("token", "", {
        path: "/",
        httpOnly: true,
        expires: new Date(0),
        sameSite: "none",
        secure: true,
    });
    res.status(200).json({ message: "Logout successful" })
})

// Get User
const getUser = asyncHandler (async (req, res) => {
    const user = await User.findById(req.user._id)

    if (user) {
        const { _id, name, email, phone, bio, photo, role, isVerified } = user;
        res.status(200).json({
            _id,
            name,
            email,
            phone,
            bio,
            photo,
            role,
            isVerified,
        });
    } else {
        res.status(404);
        throw new Error("User not found");
    }
})

// Update User
const updateUser = asyncHandler (async (req, res) => {
    
    const user = await User.findById(req.user._id);

    if (user) {
        const { name, email, phone, bio, photo, role, isVerified } = user;

        user.email = email
        user.name = req.body.name || name
        user.phone = req.body.phone || phone
        user.bio = req.body.bio || bio
        user.photo = req.body.photo || photo

        const updatedUser = await user.save();

        res.status(200).json({
            _id: updatedUser._id,
            name: updatedUser.name,
            email: updatedUser.email,
            phone: updatedUser.phone,
            bio: updatedUser.bio,
            photo: updatedUser.photo,
            role: updatedUser.role,
            isVerified: updatedUser.isVerified,
        });

    } else {
        res.status(404);
        throw new Error("User nopt found.");
    }

})

// Delete User
const deleteUser = asyncHandler (async (req, res) => {
    
    const user = await User.findById(req.params.id);

    if (!user) {
        res.status(404);
        throw new Error("User not found.");
    }

    await user.deleteOne();
    res.status(200).json({ message: "User deleted successfully." });

});

// Get all Users
const getUsers = asyncHandler (async (req, res) => {
    const users = await User.find().sort("-createdAt").select("-password");
    if (!users) {
        res.status(500);
        throw new Error("Something went wrong");
    }
    res.status(200).json(users);
});

// Get login Status
const loginStatus = asyncHandler (async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json(false)
    }

    // Verify token
    const verified = jwt.verify(token, process.env.JWT_SECRET);

    if (verified) {
        return res.json(true);
    }
    return res.json(false);

});

const upgradeUser = asyncHandler (async (req, res) => {
    const { role, id } = req.body;

    const user = await User.findById(id);

    if (!user) {
        res.status(500);
        throw new Error("User not found.")
    }

    user.role = role;
    await user.save()

    res.status(200).json({ message: `User role updated to ${role}` })

})

module.exports = {
    registerUser,
    loginUser,
    logoutUser,
    getUser,
    updateUser,
    deleteUser,
    getUsers,
    loginStatus,
    upgradeUser
};