import { Sequelize } from 'sequelize-typescript';
import { config } from '../config';
import User from './user.model';

export const sequelize = new Sequelize({
  dialect: 'postgres',
  host: config.db.host,
  port: config.db.port,
  username: config.db.username,
  password: config.db.password,
  database: config.db.database,
  models: [User],
  logging: false,
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: false, // for most managed Postgres services
    },
  },
});