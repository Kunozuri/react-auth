// app.js
import express from 'express';
import userAuthRouter from './routes/auth.routes.js';

const app = express();

app.use(express.json());
app.use('/api/auth', userAuthRouter);

app.get('/', (req, res) => {
    res.send('welcome to the app api');
});

export default app;