import express from 'express'
 import dotenv from 'dotenv'
 import cors from 'cors'
 import morgan from 'morgan';
 import helmet from 'helmet'
 import connectedDb from './config/db.js';
 import cookieParser from 'cookie-parser';
 import userRoute from './routes/userRoute.js'
 dotenv.config()
 
 const PORT = process.env.PORT || 4001;
 const app = express()
 
 app.use(express.json())
 app.use(morgan())
 app.use(cookieParser())
 app.use(cors({
     credentials : true, 
     origin : process.env.FRONTEND_URL
 }))
 app.use(helmet({
     crossOriginEmbedderPolicy : false
 }))
 

 app.use('/api/user', userRoute)
 
 app.listen(PORT, () => {
     console.log(`The server is connecting at ${PORT} Successfully . . . . . .`)
     connectedDb()
 })