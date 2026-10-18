// server.js
import app from './app.js';
import { PORT, BASE_URI } from './config/env.js';
import connectToDatabase from './config/mongodb.js';

const startServer = async () => {
    await connectToDatabase(); // connect first, so no requests arrive before the DB is ready

    app.listen(PORT, () => {
        console.log(`server running on ${BASE_URI}${PORT}`);
    });
};

// better: catch errors so a failed startup doesn't go unhandled
startServer().catch((error) => {
    console.error('failed to start server:', error);
    process.exit(1);
});