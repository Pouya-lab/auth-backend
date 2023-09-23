const mongoose = require('mongoose');
const Schema = mongoose.Schema

const tokenSchema = new mongoose.Schema(
    {
        userId : {
            type : mongoose.Schema.Types.ObjectId,
            required : true  ,
            ref : "user" ,
        },
        //verificartionToken
        vToken : {
            type : String,
            default : "" ,
        },
        //resetToken
        rToken : {
            type : String,
            default : "" ,
        },
        //logintoken
        lToken : {
            type : String,
            default : "" ,
        },
        createdAt : {
            type : Date,
            required : true ,
        },
        expiresAt : {
            type : Date,
            required : true ,
        },
    },
    
    
)


module.exports = mongoose.model('Token' , tokenSchema)