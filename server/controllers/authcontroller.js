// MERN_AUTHENTICATION/server/controllers/authcontroller.js to store user registration and login logic in database

import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import UsersModel from '../models/usersmodel.js';
export const register = async (req,res)=>{
    const {name,email,password} = req.body; 

//if statemenrt to check missing details

    if(!name || !email || !password){
        return res.json({success:false,message:"Missing required details"})
    }
    //check if user already exists
    try{
        const existingUser = await UsersModel.findOne({email});
        
        if(existingUser){
            return res.json({success:false,message:"User already exists"});
        }
        //hash password to store securely with bcryptjs

        const hashedPassword = await bcrypt.hash(password,10);
        // create new user instance
        const newUser = new UsersModel({name,email,password:hashedPassword})
        await newUser.save();

        //generate token using jwt sending user for authentication
        const token = jwt.sign({userId:newUser._id},process.env.JWT_SECRET,{expiresIn:'7d'});
        //set token in httpOnly cookie for security
        res.cookie('token',token,{httpOnly:true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        maxAge: 7*24*60*60*1000});  // 7 days expire time for thia cookie
        return res.json({success:true,message:"Registration successful"});

      
        //sending welcome email to the user after successful registration
        

        
    }
    //if any error occurs then catch block will handle it 
    catch(error){
        res.json({success:false,message:error.message})
    }
}



//login functionality to the user
export const login = async (req,res)=>
{
    // destructure email and password from request body
    const {email,password} = req.body;
  // check for missing details
    if(!email || !password){

        return res.json({success:false,message:"Missing required details"})
    }
    // try to find user and validate password
    try{
        const existingUser = await UsersModel.findOne({email});
        // if user not found return invalid mail message
        if(!existingUser){
            return res.json({success: false,message:"invalid mail"})
        }
        // compare provided password with stored hashed password
        const isPasswordCorrect = await bcrypt.compare(password,existingUser.password);
        // if password does not match return invalid credentials message
        if(!isPasswordCorrect){
            return res.json({success:false,message:"Invalid password"})

        }
        // generate jwt token for authenticated user
        const token = jwt.sign({userId:existingUser._id},process.env.JWT_SECRET,{expiresIn:'7d'});
        //set token in httpOnly cookie for security
        res.cookie('token',token,{httpOnly:true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        maxAge: 7*24*60*60*1000});  // 7 days expire time for thia cookie

        return res.json({success:true,message:"Login successful"});



    }
    catch(error)
    {
        res.json({success:false,message:error.message})
    };
}

//logout functionality 
export const logout =async(req,res)=>
{   // clear the token cookie to logout user
    try{
        res.clearCookie('token',{
            
            httpOnly:true,
            // set secure and sameSite attributes based on environment
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        });
        // send success response

        return res.json({success:true,message:"logout successful"});
        
    }
    // catch any errors during logout process
    catch(error)
    {   // send error response
        return res.json({success:false,message:error.message})
    }
}