import app from './app';
import { sequelize } from './models';

const PORT = process.env.PORT || 5000;

async function start() {
  try {
    // await sequelize.authenticate();
    // console.log('Database connected ✅');

    // await sequelize.sync({ alter: true }); // Or use { force: true } in dev

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Unable to connect to the database:', err);
    process.exit(1);
  }
}

start();
