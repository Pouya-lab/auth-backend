const mongoose = require('mongoose');
const bcrypt = require('bcryptjs')
const Schema = mongoose.Schema

const userSchema = new mongoose.Schema(
    {
        name : {
            type : String,
            required : [true , "Please add a name"] ,
        },
        email : {
            type : String,
            required : [true , "Please add an email"] ,
            unique : true ,
            // trim for no space between email letters
            trim : true,
            //for checkin if email is a valid one 
            match : [
                /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
                "Please enter a valid email",
            ],
        },
        password :{
            type : String,
            required : [ true , "Please add a password" ]
        },
        photo : {
            type : String,
            default : "hi photo"
        },
        phone :{
            type : String,
            default : "+12345"
        },
        bio :{
            type : String,
            default : "bio"
        },
        role :{
            type : String,
            required : true  ,
            default : "subscriber"
            //subscriber author admin suspended
        },
        isVerified :{
            type : Boolean,
            default : false
            //should be false because initially user is not verified
        },
        //for checking which device is user using to come to app
        userAgent :{
            type : Array,
            required : true ,
            default : [],
        },
    },
    
    {
        //for updated at and created at
        timestamps : true , 
        //for not having a empty obj in database
        minimize : false ,
    }
)

//encrypt password before saving to DB
userSchema.pre("save" , async function (next){
    if (!this.isModified("password")) {
        return next()
    }
    //hash password
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(this.password , salt)
    this.password = hashedPassword
    next()
} )

module.exports = mongoose.model('User' , userSchema)