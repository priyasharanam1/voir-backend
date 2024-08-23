import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

app.use(cors({
    origin:process.env.CORS_ORIGIN,
    credentials:true
}))

//when we are accepting dasta from forms
app.use(express.json({limit: "16kb"}))

//when we are accepting data from url
app.use(express.urlencoded({

    extended:true,
    limit:"16kb"
}))

//to store static files like images, favicons and videos etc.
app.use(express.static("public"))

app.use(cookieParser())

export { app }