import mongoose, { Schema } from "mongoose";
import brcypt from "bcrypt";
import jwt from "jsonwebtoken"
import crypto from "crypto";

const UserSchema = new Schema({
    avatar: {

        type:{
            url: String,
            localpath: String,
        },
        default:{
            url: `https://placehold.co/200*200`,
            localpath:""
        }
    },
    username: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    email:{
        type: String,
        required: true,
        unique:true,
        trim: true
    },
    fullName: {
        type: String,
        trim: true
    },
    password: {
        type: String,
        required: true[true, "password is required"]
    },
    isEmailVerifed: {
        type:Boolean,
        default: false
    },
    refreshToken: {
        type: String
    },
    forgotPasswordToken:{
        type:String
    },
    forgotPasswordExpiry: {
        type: Date
    },
    emailVerificationToken: {
        type: String
    },
    emailVerificationExpiry:{
        type:Date
    }

},
    {
       timestamps: true
    }

);
UserSchema.pre("save", async function(next){
    if(!this.isModified("password")) return next()

    this.password = await brcypt.hash(this.password, 10)
    next()
});

UserSchema.methods.ispasswordCorrect = async function
    (password) {
       return await brcypt.compare(password, this.password);
    };
UserSchema.methods.generateAccessToken = function(){
jwt.sign(
    {
       id: this._id,
       email:this.username
    },
    process.env.ACCESS_TOKEN_SECERT,
    {expiresIn: process.env.ACCESS_TOKEN_EXPIRY}
)
}

UserSchema.methods.generateRefreshToken = function(){
   return jwt.sign(
    {
        _id:this._id,
        email:this.email,
        username: this.username

    },
    process.env.REFRESH_TOKEN_SECRET,
    {expiresIn: process.env.REFRESH_TOKEN_SECRET}
)
}

UserSchema.methods.generateTemporaryToken = function (){
  const unHashedToken = crypto.randomBytes(20).toString("hex")

  const hashedToken = crypto
  .createHash("sha256")
  .update(unHashedToken)
  .digest("hex")

  const tokenExpiry = Date.now() + (20*60*1000) // 20 mins
  return {unHashedToken, hashedToken, tokenExpiry}

};
export const User = mongoose.model("User", UserSchema)