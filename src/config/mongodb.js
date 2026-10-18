// config/db.js
import mongoose from "mongoose";
import { DB_URI, NODE_ENV } from "./env.js";

if (!DB_URI) {
    throw new Error("please define a DB_URI environment variable inside .env.<development/production>.local");
}

const connectToDatabase = async () => {
    try {
        await mongoose.connect(DB_URI);
        console.log(`connected to database in ${NODE_ENV} mode`);
    } catch (error) {
        console.error("error connecting to database:", error);
        process.exit(1); // no point running the API without a database
    }
};

export default connectToDatabase;