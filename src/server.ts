import app from './app';
import { sequelize } from './models';
import { config } from './config/index';


const PORT = config.port || 5000;

async function start() {
  try {
    await sequelize.authenticate();

    await sequelize.sync({ alter: true }); // Or use { force: true } in dev

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Unable to connect to the database:', err);
    process.exit(1);
  }
}

start();