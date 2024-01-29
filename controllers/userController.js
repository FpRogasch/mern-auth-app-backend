const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const bcrypt = require("bcryptjs");
const { generateToken, hashToken } = require("../utils");
var parser = require("ua-parser-js");
const jwt = require("jsonwebtoken");
const sendEmail = require("../utils/sendEmail");
const Token = require("../models/tokenModel");
const crypto = require("crypto");
const Cryptr = require("cryptr");
const { OAuth2Client } = require("google-auth-library");

const cryptr = new Cryptr(process.env.CRYPTR_KEY);
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

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
    const ua = parser(req.headers["user-agent"]);
    const thisUserAgent = ua.ua;
    console.log(thisUserAgent);

    const allowwedAgent = user.userAgent.includes(thisUserAgent)

    if (!allowwedAgent) {
        // Generate 6 digit code
        const loginCode = Math.floor( 100000 + Math.random() * 900000);
        console.log(loginCode);

        // Encrypt login code before saving to DB
        const encryptedLoginCode = cryptr.encrypt(loginCode.toString());

        // Delete token if exists in DB
        let userToken = await Token.findOne({ userId: user._id })
        if (userToken) {
            await userToken.deleteOne();
        }
        
        // Save token to DB
        await new Token({
            userId: user._id,
            lToken: encryptedLoginCode,
            createdAt: Date.now(),
            expiresAt: Date.now() + 60 * (60 * 1000) // 1 hour
        }).save();

        res.status(400);
        throw new Error("New browser or divice detected.")
    }

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

});

// Send Login Code
const sendLoginCode = asyncHandler (async (req, res) => {
    
    const { email } = req.params;
    const user = await User.findOne({ email });

    if (!user) {
        res.status(404);
        throw new Error("User not found");
    }

    // Find Login Code in DB
    let userToken = await Token.findOne({ 
        userId: user._id,
        expiresAt: {$gt: Date.now()}
    });

    if (!userToken) {
        res.status(404);
        throw new Error("Invalid or Expired token, please login again.");
    }

    const loginCode = userToken.lToken;
    const decryptedLoginCode = cryptr.decrypt(loginCode);

    // Send Login Code Email
    const subject = "Login Access Code - AUTH:Z";
    const send_to = email;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = "noreply@felipe.com";
    const template = "loginCode";
    const name = user.name;
    const link = decryptedLoginCode;

    try {
        await sendEmail(
            subject,
            send_to,
            sent_from,
            reply_to,
            template,
            name,
            link
        );
        res.status(200).json({ message: `Access Login Code sent to ${email}` });
    } catch (err) {
        res.status(500);
        throw new Error("Email not sent, please try again.")
    }

})

// Login With Code
const loginWithCode = asyncHandler (async (req, res) => {
    
    const { email } = req.params;
    const { loginCode } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
        res.status(404);
        throw new Error("User not found");
    }

    // Find user login token
    const userToken = await Token.findOne({
        userId: user.id,
        expiresAt: { $gt: Date.now() },
    });

    if (!userToken) {
        res.status(404);
        throw new Error("Invalid or Expired Token, please login again");
    }

    const decryptedLoginCode = cryptr.decrypt(userToken.lToken);
    if (loginCode !== decryptedLoginCode) {
        res.status(400);
        throw new Error("Incorrect login Code, please try again.")
    } else {

        // Register userAgent
        const ua = parser(req.headers["user-agent"]);
        const thisUserAgent = ua.ua;
        user.userAgent.push(thisUserAgent)

        await user.save()

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
            token
        });
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
});

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
});

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

});

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

// Upgrade User
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

// Send Automated emails
const sendAutomatedEmail = asyncHandler (async (req, res) => {
    const { subject, send_to, reply_to, template, url } = req.body;

    if (!subject || !send_to || !reply_to || !template) {
        res.status(500);
        throw new Error("Missing email prameter.");
    }

    // Get User
    const user = await User.findOne({ email: send_to })

    if (!user) {
        res.status(404);
        throw new Error("User not found.")
    }

    const sent_from = process.env.EMAIL_USER
    const name = user.name
    const link = `${process.env.FRONTEND_URL}${url}`

    try {
        await sendEmail(subject, 
                        send_to, 
                        sent_from, 
                        reply_to, 
                        template, 
                        name, 
                        link )
        res.status(200).json({ message: "Email Sent" })

    } catch (err) {
        res.status(500);
        throw new Error("Email not sent, plese try again.")
    }

})

// Send Verification emails
const sendVerificationEmail = asyncHandler (async (req, res) => {
    
    const user = await User.findById(req.user._id)

    if (!user) {
        res.status(404);
        throw new Error("User not found, please signup");
    }

    if (user.isVerified) {
        res.status(400);
        throw new Error("User already verified.");
    }

    // Delete token if exists in DB
    let token = await Token.findOne({ userId: user._id })
    if (token) {
        await token.deleteOne();
    }

    // Create Verification Token and Save it
    const verificationToken = crypto.randomBytes(32).toString("hex") + user._id;
    console.log(verificationToken);
    
    // Hash token and save
    const hashedToken = hashToken(verificationToken)
    await new Token({
        userId: user._id,
        vToken: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * (60 * 1000) // 1 hour
    }).save()

    // Construct Verification URL
    const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`

    // Send verification Email
    const subject = "Verify your Account - AUTH:Z";
    const send_to = user.email;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = "noreply@felipe.com";
    const template = "verifyEmail";
    const name = user.name;
    const link = verificationUrl;

    try {
        await sendEmail(
            subject,
            send_to,
            sent_from,
            reply_to,
            template,
            name,
            link
        );
        res.status(200).json({ message: "Verification Email Sent" });
    } catch (err) {
        res.status(500);
        throw new Error("Email not sent, please try again.")
    }

})

// Verify User
const verifyUser = asyncHandler (async (req, res) => {
    
    const { verificationToken } = req.params

    const hashedToken = hashToken(verificationToken)

    const userToken = await Token.findOne({
        vToken: hashedToken,
        expiresAt: {$gt: Date.now()}
    })

    if (!userToken) {
        res.status(404);
        throw new Error("Invalid or Expired Token");
    }

    // Find User
    const user = await User.findOne({ _id: userToken.userId });

    if (user.isVerified) {
        res.status(400);
        throw new Error("User is already verified.");
    }

    // Now verify user
    user.isVerified = true
    await user.save();

    res.status(200).json({ message: "Account Verfication Successful" });

})

// Forgot Password
const forgotPassword = asyncHandler (async (req, res) => {
    
    const { email } = req.body

    const user = await User.findOne({email});

    if (!user) {
        res.status(404);
        throw new Error("No user woth this email.");
    }

    // Delete token if exists in DB
    let token = await Token.findOne({ userId: user._id })
    if (token) {
        await token.deleteOne();
    }

    // Create resetToken Token and Save it
    const resetToken = crypto.randomBytes(32).toString("hex") + user._id;
    console.log(resetToken);
    
    // Hash token and save
    const hashedToken = hashToken(resetToken)
    await new Token({
        userId: user._id,
        rToken: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * (60 * 1000) // 1 hour
    }).save();

    // Construct Reset URL
    const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`

    // Send verification Email
    const subject = "Password Reset Request - AUTH:Z";
    const send_to = user.email;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = "noreply@felipe.com";
    const template = "forgotPassword";
    const name = user.name;
    const link = resetUrl;

    try {
        await sendEmail(
            subject,
            send_to,
            sent_from,
            reply_to,
            template,
            name,
            link
        );
        res.status(200).json({ message: "Password Reset Email Sent" });
    } catch (err) {
        res.status(500);
        throw new Error("Email not sent, please try again.")
    }

});

// Reset Password
const resetPassword = asyncHandler (async (req, res) => {
    
    const {resetToken} = req.params;
    const {password} = req.body;

    const hashedToken = hashToken(resetToken)

    const userToken = await Token.findOne({
        rToken: hashedToken,
        expiresAt: {$gt: Date.now()}
    })

    if (!userToken) {
        res.status(404);
        throw new Error("Invalid or Expired Token");
    }

    // Find User
    const user = await User.findOne({ _id: userToken.userId });

    // Now reset Password
    user.password = password;
    await user.save();

    res.status(200).json({ message: "Password Reset Successful, please login." });

})

// Change Password
const changePassword = asyncHandler (async (req, res) => {

    const { oldPassword, password } = req.body
    const user = await User.findById(req.user._id)

    if (!user) {
        res.status(404);
        throw new Error("User not found");
    }

    if (!oldPassword || !password) {
        res.status(404);
        throw new Error("Please enter old and new password");
    }

    // Check if old password is correct
    const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password)

    // Save new password
    if (user && passwordIsCorrect) {
        user.password = password;
        await user.save();

        res.status(200).json({ message: "Password changed successful, please re-login." });
    } else {
        res.status(400);
        throw new Error("Old password is incorrect");
    }

});

// Login With Google
const loginWithGoogle = asyncHandler (async (req, res) => {
    const {userToken} = req.body;
    // console.log(userToken);

    const ticket = await client.verifyIdToken({
        idToken: userToken,
        audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { name, email, picture, sub } = payload;
    const password = Date.now() + sub

    // Get user Agent
    const ua = parser(req.headers['user-agent']);
    const userAgent = [ua.ua]

    // Check if user exists
    const user = await User.findOne({ email });

    if (!user) {
        // Create new user
        const newUser = await User.create({
            name,
            email,
            password,
            photo: picture,
            isVerified: true,
            userAgent,
        });

        if (newUser) {        
            // Generate Token
            const token = generateToken(newUser._id);

            // Send HTTP-only cookie
            res.cookie("token", token, {
                path: "/",
                httpOnly: true,
                expires: new Date(Date.now() + 1000 * 86400), // 1 day
                sameSite: "none",
                secure: true,
            });

            const { _id, name, email, phone, bio, photo, role, isVerified } = newUser;

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
            })
        }
    }

    // User exists login
    if (user) {
        const token = generateToken(user._id);

        // Send HTTP-only cookie
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // 1 day
            sameSite: "none",
            secure: true,
        });

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
        })
    }

});

module.exports = {
    registerUser,
    loginUser,
    logoutUser,
    getUser,
    updateUser,
    deleteUser,
    getUsers,
    loginStatus,
    upgradeUser,
    sendAutomatedEmail,
    sendVerificationEmail,
    verifyUser,
    forgotPassword,
    resetPassword,
    changePassword,
    sendLoginCode,
    loginWithCode,
    loginWithGoogle
};