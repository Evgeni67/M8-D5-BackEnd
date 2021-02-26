const jwt = require("jsonwebtoken")
const UserModel = require("../services/users/schema")
const { verifyJWT } = require("./tools")

const authorize = async (req, res, next) => {
  try {
    console.log(req.header("Authorization").replace("Bearer ", ""))
    const token = req.header("Authorization").replace("Bearer ", "")
    try{
      const decoded = await verifyJWT(token)

    }catch(e){
      console.log("verifyJWT problem")
    }
    console.log(decoded)
    const user = await UserModel.findOne({
      _id: decoded._id,
    })

    if (!user) {
      throw new Error()
    }

    req.token = token
    req.user = user
    next()
  } catch (e) {
    const err = new Error("Please authenticate")
    err.httpStatusCode = 401
    next(err)
  }
}

const adminOnlyMiddleware = async (req, res, next) => {
  if (req.user && req.user.role === "admin") next()
  else {
    const err = new Error("Only for admins!")
    err.httpStatusCode = 403
    next(err)
  }
}

module.exports = { authorize, adminOnlyMiddleware }
