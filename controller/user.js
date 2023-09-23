const asyncHandler = require('express-async-handler')
const User = require('../model/user')
const bcrypt = require('bcryptjs')
const { generateToken, hashToken } = require('../util')
var parser = require('ua-parser-js')
const jwt = require('jsonwebtoken')
const { sendEmail } = require('../util/sendEmail')
const Token = require('../model/token')
const crypto = require("crypto")
const token = require('../model/token')
const Cryptr = require('cryptr');
const cryptr = new Cryptr(process.env.CRYPTR_KEY);

exports.registerUser = asyncHandler( 
    async (req , res ) =>{
        const { name , email , password } = req.body

        //validation
        if (!name || !email || !password) {
            res.status(400)
            throw new Error('Please fill all the required fields ')
        }

        if (password.length < 6) {
            res.status(400)
            throw new Error('Password should be more than six Characters')
        }

        //if user exists
        const userExists = await User.findOne({email})
        if (userExists) {
            res.status(400)
            throw new Error('Email has already been registered')
        }

        //get user agent
        const ua = parser(req.headers['user-agent'])
        const userAgent = [ua.ua]

        //create new user
        const user = await User.create({
            name , 
            email ,
            password,
            userAgent
        })

        //generate token
        const token = generateToken(user._id)

        //send http only cookie
        res.cookie("token" , token , {
            path : '/',
            httpOnly : true ,
            expires : new Date(Date.now() + 1000 * 86400) ,//expires after a day
            sameSite : 'none', //for checking if the front and back are in the same site
            secure : true, //for deploy should be true but during development can be false
        })


        if (user) {
            const { _id , name , email , phone , bio , photo , role , isVerified } = user


            res.status(201).json({
                _id ,
                name , 
                email , 
                phone , 
                bio , 
                photo , 
                role , 
                isVerified , 
                token
            })

        }
        else
        {
            res.status(400)
            throw new Error('Invalid user data!! ')
        }

    }
 ) 
 
 //send verification email
 exports.sendVerificationEmail = asyncHandler( async( req , res )=>{
    
    const user = await User.findById(req.user._id)

    if(!user){
        res.status(404)
        throw new Error("user not found!! Please sign up")
    }

    if(user.isVerified){
        res.status(400)
        throw new Error("user is already verified")
    }
    //delete token if it exists in DB
    let token = await Token.findOne({ 
        userId : user._id 
    })
    if(token){
        await token.deleteOne()
    }

    //create verification token and save to DB
    const verificationToken = crypto.randomBytes(32).toString("hex") + user._id
    console.log(verificationToken);

    //hash Token and save
    const hashedToken = hashToken(verificationToken)
    await new Token({
        userId : user._id ,
        vToken : hashedToken ,
        createdAt : Date.now(),
        expiresAt : Date.now() + 60*(60*1000) //60 minutes
    }).save()

    //construct verification URL
    const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`

    //send Email
   const subject = "Verify your account"
   const send_to = user.email
   const sent_from = process.env.EMAIL_USER
   const reply_to = "no@mail.com"
   const template = "verifyEmail"
   const name = user.name
   const link = verificationUrl

   try {
    await sendEmail(
        subject ,
        send_to ,
        sent_from ,
        reply_to ,
        template ,
        name , 
        link
    )
    res.status(200).json({ mssg : "email sent"})
    } 
    catch (error) {
        res.status(500)
        throw new Error("email did not send try again later")
    }
    
 } )

 //verify User
 exports.verifyUser = asyncHandler(async ( req , res )=>{
    const { verificationToken } = req.params

    const hashedToken = hashToken(verificationToken)

    const userToken = await token.findOne({
        vToken : hashedToken ,
        expiresAt : { $gt : Date.now() }
    })
    if(!token){
        res.status(404);
        throw new Error("expired Token");
    }

    //find user
    const user = await User.findOne({ _id : userToken.userId })

    if(user.isVerified){
        res.status(400);
        throw new Error("user is already verified");
    }

    //now verify user
    user.isVerified = true
    await user.save()

    res.status(200).json({ mssg : "account verification successful" });

 })

 //checking for login user validation with backend data
 //how we login a user?? => by sending cookies to clients(browser)
exports.loginUser = asyncHandler( async (req , res)=>{
    const { email , password } = req.body

    //validation
    if( !email || !password ){
        res.status(400)
        throw new Error("Please add email or password!!")
    }

    //if user exists
    const user = await User.findOne({ email })

    //if user does not exists
    if(!user){
        res.status(404)
        throw new Error("user not found!! Please sign up")
    }

    //comparing the given password with the hashed password in database
    const passwordIsCorrect = await bcrypt.compare(password , user.password)
    if(!passwordIsCorrect){
        res.status(400)
        throw new Error("Password is not correct")
    }

    //trigger 2factor authentication for user device that is using to connect
    const ua = parser(req.headers["user-agent"])
    const thisUserAgent = ua.ua 
    console.log(thisUserAgent);

    const allowedAgent = user.userAgent.includes(thisUserAgent)

    if(!allowedAgent){
        //generate 6 digit code
        const loginCode = Math.floor( 100000 + Math.random() * 900000 )
        console.log(loginCode);

        //encrypt login code before saving in database
        const encryptedLoginCode = cryptr.encrypt(loginCode.toString())

        let userToken = await Token.findOne({ 
            userId : user._id 
        })
        if(userToken){
            await userToken.deleteOne()
        }
    
        //save Token to db
        await new Token({
            userId : user._id ,
            lToken : encryptedLoginCode ,
            createdAt : Date.now(),
            expiresAt : Date.now() + 60*(60*1000) //60 minutes
        }).save()

        res.status(400)
        throw new Error("Check your email for login code")

    }

    //now that everything is alright we have to login the user

    //generate Token for the action
    const token = generateToken(user._id)
    if (user && passwordIsCorrect) {

        res.cookie("token" , token , {
            path : '/',
            httpOnly : true ,
            expires : new Date(Date.now() + 1000 * 86400),
            sameSite : "none",
            secure : true
            //TODO change secure to true for connecting to frontend
            //TODO this is needed to be true for 
        })
        //sending datas from DB to front
        const { _id , name , email , phone , bio , photo , role , isVerified } = user
            res.status(200).json({
                _id ,
                name , 
                email , 
                phone , 
                bio , 
                photo , 
                role , 
                isVerified , 
                token
            })        

    }
    else{
        res.status(500)
        throw new Error("Something went wrong!! Please try again")
    }

} )

exports.sendLoginCode = asyncHandler(async ( req , res )=>{
    const { email } = req.params

    const user = await User.findOne({ email })

    if(!user){
        res.status(404)
        throw new Error("User not found")
    }

    //find login code in DB
    let userToken = await Token.findOne({ 
        userId : user._id,
        expiresAt : { $gt: Date.now()}
    })

    if(!userToken){
        res.status(404)
        throw new Error("invalid or expired token!!! Please login again")
    }

    const loginCode = userToken.lToken
    const decryptLoginCode = cryptr.decrypt(loginCode)

//login access code
   const subject = "Login access Code"
   const send_to = email
   const sent_from = process.env.EMAIL_USER
   const reply_to = "no@mail.com"
   const template = "loginCode"
   const name = user.name
   const link = decryptLoginCode

   try {
    await sendEmail(
        subject ,
        send_to ,
        sent_from ,
        reply_to ,
        template ,
        name , 
        link
    )
    res.status(200).json({ mssg : `access code sent to ${email}`})
    } 
    catch (error) {
        res.status(500)
        throw new Error("email did not send try again later")
    }

})

exports.loginWithCode = asyncHandler(async( req , res )=>{
    const { email } = req.params;
  const { loginCode } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  // Find user Login Token
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
    throw new Error("Incorrect login code, please try again");
  } else {
    // Register userAgent
    const ua = parser(req.headers["user-agent"]);
    const thisUserAgent = ua.ua;
    user.userAgent.push(thisUserAgent);
    await user.save();

    // Generate Token
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
    });
  }

})

//logout user
exports.logoutUser = asyncHandler( async (req , res)=>{
    //expire cookie to logout user and for token value we send empty string 
    res.cookie("token" , "" , {
        path : '/',
        httpOnly : true ,
        expires : new Date(0), //this time is going to expire the user and kick them out
        sameSite : "none",
        secure : true
    })
    return res.status(200).json({ mssg : "Logout successful" })
})

//for getting each user loged in in our app
exports.getUser = asyncHandler(async (req , res)=>{
    const user = await User.findById( req.user._id )

    if (user) {
        const { _id , name , email , phone , bio , photo , role , isVerified } = user
            res.status(200).json({
                _id ,
                name , 
                email , 
                phone , 
                bio , 
                photo , 
                role , 
                isVerified , 
            })        
    }else{
        res.status(404)
        throw new Error("User not found")
    }
})
    //for updating users data
exports.updateUser = asyncHandler(async (req , res)=>{
    const user = await User.findById(req.user._id)

    if (user) {
        const { name , email , phone , bio , photo , role , isVerified } = user
        // if the name has updated its ok but if its not it should be ok too so we add \\ name to it
        user.email = req.body.email || email
        user.name = req.body.name || name
        user.phone = req.body.phone || phone
        user.bio = req.body.bio || bio
        user.photo = req.body.photo || photo

        const updatedUser = await user.save()
        //sends the updated data to front
        res.status(200).json({ 
            name : updatedUser.name , 
            email : updatedUser.email, 
            phone : updatedUser.phone, 
            bio : updatedUser.bio, 
            photo : updatedUser.photo , 
            role : updatedUser.role, 
            isVerified : updatedUser.isVerified, 
        })    


    } else {
        res.status(404)
        throw new Error("User not found")
    }
})


exports.deleteUser = asyncHandler(async (req , res)=>{
    //get params
    const user = User.findById(req.params.id)
     if (!user) {
        res.status(404)
        throw new Error("user  not found!!")
    }
    await user.deleteOne()
    res.status(200).json({ mssg : "User deleted succesfully!! "})
})

exports.getUsers = asyncHandler(async (req , res)=>{
    const users = await User.find().sort("-createdAt").select("-password")
    if(!users){
        res.status(500)
        throw new Error("Something went wrong")
    }
    res.status(200).json(users)
})

exports.loginStatus = asyncHandler(async (req , res)=>{
    const token = req.cookies.token

    if(!token){
        return res.json(false)
    }

    //verify token
    const verified =  jwt.verify( token , process.env.JWT_SECRET )

    if(verified){
        return res.json(true)
    }else{
        return res.json(false)
    }

})

exports.upgradeUser = asyncHandler(async(req , res)=>{
    //for upgrading a user we need to update role and id together
    const { role , id } = req.body

    const user = await User.findById(id)

    if(!user){
        res.status(500)
        throw new Error("user not found")
    }
    //user.role is equal to the role we recieved from body{code above}
    user.role = role
    await user.save()

    res.status(200).json({mssg : `user role updated to ${role}`})

})

exports.sendAutomatedEmail = asyncHandler(async (req , res)=>{
    const { subject , send_to , reply_to , template , url  } = req.body

    if(!subject || !send_to || !reply_to || !template){
        res.status(404)
        throw new Error("missing email parameter")
    }

    // get user
    const user = await User.findOne({ email : send_to })
    if(!user){
        res.status(404)
        throw new Error("user not found")
    }

    const sent_from = process.env.EMAIL_USER
    const name = user.name
    const link = `${process.env.FRONTEND_URL}${url}`
    
    try {
        await sendEmail(
            subject ,
            send_to ,
            sent_from ,
            reply_to ,
            template ,
            name , 
            link
        )
        res.send(200).json({ mssg : "email sent"})
    }
    catch (error) {
        res.status(500)
        throw new Error("email did not send try again later")
    }
})

exports.forgotPass = asyncHandler(async ( req , res )=>{
    const { email } = req.body

    const user = await User.findOne({ email })

    if(!user){
        res.status(404)
        throw new Error("User does not exists with this email")
    }

    let token = await Token.findOne({ 
        userId : user._id 
    })
    if(token){
        await token.deleteOne()
    }

    //create verification token and save to DB
    const resetToken = crypto.randomBytes(32).toString("hex") + user._id
    console.log(resetToken);

    //hash Token and save
    const hashedToken = hashToken(resetToken)
    await new Token({
        userId : user._id ,
        rToken : hashedToken ,
        createdAt : Date.now(),
        expiresAt : Date.now() + 60*(60*1000) //60 minutes
    }).save()

    //construct reset URL to go to front page
    const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`

    //send Email
   const subject = "Password reset Request"
   const send_to = user.email
   const sent_from = process.env.EMAIL_USER
   const reply_to = "no@mail.com"
   const template = "forgottenPass"
   const name = user.name
   const link = resetUrl

   try {
    await sendEmail(
        subject ,
        send_to ,
        sent_from ,
        reply_to ,
        template ,
        name , 
        link
    )
    res.status(200).json({ mssg : "password reset request granted"})
    } 
    catch (error) {
        res.status(500)
        throw new Error("email did not send try again later")
    }
})

exports.resetPass = asyncHandler(async (req , res)=>{
    const { resetToken } = req.params
    const { password } = req.body

    const hashedToken = hashToken(resetToken)

    const userToken = await token.findOne({
        rToken : hashedToken ,
        expiresAt : { $gt : Date.now() }
    })
    if(!token){
        res.status(404);
        throw new Error("expired Token");
    }

    //find user
    const user = await User.findOne({ _id : userToken.userId })

    //now reset user
    user.password = password
    await user.save()

    res.status(200).json({ mssg : "Password Reset Successful, please login" }); 

})

exports.changePass = asyncHandler(async (req , res)=>{
    const user = await User.findById(req.user._id)

    const { oldPassword , password } = req.body

    if(!user){
        res.status(404)
        throw new Error("User not found")
    }

    if(!oldPassword || !password){
        res.status(400)
        throw new Error("please enter both old and new password")
    }

    const passwordIsCorrect = await bcrypt.compare( oldPassword , user.password )

    if(user && passwordIsCorrect){
        user.password = password
        await user.save()
        res.status(200).json({ mssg : "password change successfully" })
    }
    else{
        res.status(400)
        throw new Error("Invalid inputs. Please try again")
    }


} )