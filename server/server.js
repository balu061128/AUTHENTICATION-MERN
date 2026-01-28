import express  from 'express';
import cors from 'cors';
import 'dotenv/config';
import cookieParser from 'cookie-parser';
import connectDB from './config/mongodb.js';
import authRouter from './routes/authroute.js';
import userRouter from './routes/userRoutes.js';


const app = express();
const PORT = process.env.PORT || 5000;

connectDB();
app.use(express.json());
app.use(cookieParser());
app.use(cors({credentials: true}));

// api endpoints
app.get('/', (req, res) => res.send("Api working fine"));
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
