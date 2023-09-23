const nodeMailer = require('nodemailer')
const hbs = require('nodemailer-express-handlebars')
const path = require('path')

//function for sending email needs some properties
exports.sendEmail = async ( subject , send_to , sent_from , reply_to , template , name , link ) =>{
    //transporter
    //enter our data for outlook such as username and pass
    const transporter = nodeMailer.createTransport({
        host : process.env.EMAIL_HOST , 
        port : 587 ,
        auth : {
            user : process.env.EMAIL_USER ,
            pass : process.env.EMAIL_PASS ,
        },
        //just set this for preventing email sending problems
        tls : {
            rejectUnauthorized : false
        }
    })


    const handleBarOptions = {
        //properties for handlebar 
        viewEngine : {
            //templates names ends with .handlebars
            //where these files are going to stand in
            extName : ".handlebars" ,
            partialsDir : path.resolve('./views'),
            defaultLayout : false
        },
        viewPath : path.resolve('./views'),
        extName : ".handlebars" ,
    }
    //running this template
    transporter.use( "compile" , hbs(handleBarOptions) )


    //options for sending email
    const options  = {
        from : sent_from , 
        to : send_to ,
        replyTo : reply_to ,
        subject ,
        template,
        //context is going to be unique for each user that we send email to
        context : {
            name ,
            link
        }

    }
    
    //send email
    transporter.sendMail(options , function ( err , info ){
        if(err){
            console.log(err);
        } else{
            console.log(info);
        }
    })
}