import mongoose from "mongoose";
 
 const connectedDb = async () => {
     try {
         await mongoose.connect(process.env.LOCAL_URL)
         console.log(`The Database is connected at ${mongoose.connection.host} Successfull . . . . . `)
     } catch (error) {
         console.log(`Database is Not Connected Error: ${error}`)
     }
 }
 
 export default connectedDb;