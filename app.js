import express from 'express';

import { PORT } from './config/env.js';

import SignInRouter from './routes/sign-in.routes.js';
import SignUpRouter from './routes/sign-up.routes.js';

const app = express();

app.use('/api/auth', SignInRouter);
app.use('/api/auth', SignUpRouter);

const BASE_URI = 'http://localhost:';

app.get('/', (req, res) => {
    res.send('welcome to the app api');
});

app.listen(PORT, () => {
    console.log(`server running on port ${BASE_URI + PORT}`);
});

export default app;