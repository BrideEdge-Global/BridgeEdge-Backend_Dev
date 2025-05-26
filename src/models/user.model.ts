import { Table, Column, Model, DataType, Default, PrimaryKey } from 'sequelize-typescript';

export interface UserAttributes {
  id?: string;
  email: string;
  password: string;
  isAdmin?: boolean;
  isCustomer?: boolean;
  isActive?: boolean;
}

@Table({ tableName: 'users', timestamps: true })
export default class User extends Model<UserAttributes, UserAttributes> {
  @PrimaryKey
  @Default(DataType.UUIDV4)
  @Column(DataType.UUID)
  id!: string;

  @Column({ type: DataType.STRING, allowNull: false, unique: true })
  email!: string;

  @Column({ type: DataType.STRING, allowNull: false })
  password!: string;

  @Default(false)
  @Column(DataType.BOOLEAN)
  isAdmin!: boolean;

  @Default(true)
  @Column(DataType.BOOLEAN)
  isCustomer!: boolean;

  @Default(true)
  @Column(DataType.BOOLEAN)
  isActive!: boolean;

  @Column({ type: DataType.STRING, allowNull: true })
  otp?: string | null; 

  @Column({ type: DataType.DATE, allowNull: true })
  otpExpires?: Date | null;

  @Default(false)
  @Column(DataType.BOOLEAN)
  isVerified!: boolean;

  // Additional fields can be added here as needed
  // For example, you might want to add timestamps or other metadata  
}