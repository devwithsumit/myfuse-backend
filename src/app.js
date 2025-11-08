import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';

import authRouter from './routes/authRoutes.js';
import adminRouter from './routes/adminRoutes.js';

const app = express();

app.use(helmet());
app.use(
    cors({
        origin: process.env.CORS_ORIGIN || '*',
        credentials: true,
    })
);
app.use(express.json({ limit: '1mb' }));
app.use(morgan('dev'));


app.get('/api/test', (req, res) => {
    res.status(200).json({ success: true, message: 'The Server is running' });
});

app.use('/api/auth', authRouter);
app.use('/api/admin', adminRouter);

app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    // eslint-disable-next-line no-console
    console.error('Unhandled error:', err);
    res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
});

export default app;


