import { Sequelize } from 'sequelize-typescript';
import { config } from '../config';
import User  from './user.model'; // import your models here

export const sequelize = new Sequelize({
  dialect: 'postgres',
  host: config.db.host,
  port: config.db.port,
  username: config.db.username,
  password: config.db.password,
  database: config.db.database,
  models: [User], // register all models here
  logging: false,
});
