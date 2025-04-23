import { Table, Column, Model, DataType } from 'sequelize-typescript';

@Table({
  tableName: 'users',
  timestamps: true,
})
class User extends Model {
  @Column({
    type: DataType.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  })
  id!: number;

  @Column({
    type: DataType.STRING,
    allowNull: false,
  })
  email!: string;

  // Add other columns here
}

export default User;