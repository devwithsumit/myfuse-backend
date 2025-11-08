import 'dotenv/config';

import app from './app.js';
import { getPool } from './config/db.js';

const PORT = process.env.PORT || 4000;

(async () => {
    try {
        await getPool().query('SELECT 1 + 1 AS result');
        app.listen(PORT, () => {
            // eslint-disable-next-line no-console
            console.log(`Server running on port ${PORT}`);
        });
    } catch (error) {
        // eslint-disable-next-line no-console
        console.error('Failed to start server due to DB connection error:', error.message);
        process.exit(1);
    }
})();


