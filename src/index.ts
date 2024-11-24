import express, { Request, Response } from "express";
import jwt from "jsonwebtoken"
import z from "zod"
import bcrypt from 'bcrypt'
import { PrismaClient } from "@prisma/client"
const cors = require("cors")

const db = new PrismaClient()


const app = express()


app.use(cors())

app.use(express.json())

const PORT = 3000
const JWT_SECRET= "my_secret"

interface User {
  username: string
  password: string
}

const users: User[] = []

const signupBody = z.object({
  username: z.string().min(1, 'Name is required'),
  password: z.string().min(8, 'Password length should be minimum of 8'),

})

const signinBody = z.object({
  username: z.string().min(1, 'Name is required'),
  password: z.string().min(8, 'Password length should be minimum of 8')
})

const authenticateToken = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  const token = req.headers.authToken;
 

  if (!token) {
    res.status(401).json({ message: "Access Denied. No token provided." });
    return; // Important: Ensure you return after sending a response
  }

  const stringifiedToken = JSON.stringify(token)
  


  try {
    const username  = jwt.verify(stringifiedToken, JWT_SECRET);
    req.body.username = username; // Attach decoded user info to the request object
    next(); // Pass control to the next middleware
  } catch (err) {
    res.status(403).json({ message: "Invalid token." });
  }
};


app.post('/signup', async (req: Request, res: Response) => {

  try {
    const body = req.body
    const result = signupBody.parse(body)

    const { username, password } = result

    let foundUser;

    console.log("request came here in signup")

     foundUser = await db.user.findFirst({
      where:{
        username:username
      }
    })

    if (foundUser) {
      res.status(400).send({ message: 'User already exists' })
    }


    const hashedPassword = await bcrypt.hash(password, 10)

   const user = await db.user.create({
      data:{
        username:username,
        password:hashedPassword
      },
    })

    console.log(user)

    users.push({
      username: username,
      password: hashedPassword
    })

    res.status(200).send({ message: 'User successfully registered' })

  } catch (error) {
    if (error instanceof z.ZodError) {
      res.status(400).send({ errors: error.errors });
    } else {
      res.status(500).send({ message: 'Internal server error' });
    }

  }





})


app.post('/signin' , async(req:Request , res:Response)=>{
  try {
    const body = req.body 
    const result = signinBody.parse(body)
    const { username , password } = result

    const foundUser = await db.user.findFirst({
      where:{
        username:username
      }
    })

    if(!foundUser){
      res.status(400).send({message: 'Invalid username '})
    }

  

    

    const isPasswordValid =  await bcrypt.compare( password ,foundUser!.password)

    if (!isPasswordValid) {
      res.status(400).send({ message: 'Invalid  password' });
      return;
    }

    const token = jwt.sign({username} , JWT_SECRET , {expiresIn:'1h'})

    res.status(200).send({
      token ,
      message: 'User successfully signed in'
    })


  }catch(error){
    if (error instanceof z.ZodError) {
      res.status(400).send({ errors: error.errors });
    } else {
      res.status(500).send({ message: 'Internal server error' });
    }
  }
})

app.get('/me' , authenticateToken , async(req, res)=>{

})

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})