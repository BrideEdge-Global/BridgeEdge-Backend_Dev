import app from './app';
import { sequelize } from './models';
import { config } from './config/index';

const PORT = config.port || 5000;

//Retry connection logic
async function connectWithRetry(retries = 5, delay = 3000) {
  for (let i = 0; i < retries; i++) {
    try {
      await sequelize.authenticate();
      await sequelize.sync({ alter: true }); // or use `force: true` in development
      return true;
    } catch (err) {
      console.error(`Unable to connect to the database (attempt ${i + 1}):`, err);
      if (i < retries - 1) {
        await new Promise(res => setTimeout(res, delay));
      } else {
        throw err;
      }
    }
  }
}

async function start() {
  try {
    await connectWithRetry(); //  retry logic here!

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Unable to connect to the database after multiple attempts:', err);
    process.exit(1);
  }
}

start();