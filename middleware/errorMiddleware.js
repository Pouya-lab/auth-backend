const errorHandler = (err , req , res , next ) => {
  const statusCode = res.statusCode ? res.statusCode : 500 

  res.status(statusCode)


  res.json({
    message : err.message ,
    stack : process.env.NODE_ENV === "development" ? err.stack : null
  })

}

module.exports = errorHandler

//this module helps us to see where does the error come from so that we could handle the problem
