const { DataTypes } = require("sequelize");
const sequelize = require("../db/dbConfig");
const Hospital = require("../model/hospitalMaster");
const Nodal = require("../model/nodalMaster");
const Doctor = require("../model/doctorRegistration");
const RoleType = require("../model/roletypeMaster");

const User = sequelize.define(
  "user",
  {
    user_id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    wattsapp_number: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    mobile_number: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    alternate_number: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    email: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    first_name: {
      type: DataTypes.STRING,
    },
    last_name: {
      type: DataTypes.STRING,
    },
    gender: {
      type: DataTypes.ENUM("Male", "Female", "Other"),
      allowNull: false,
    },
    dob: {
      type: DataTypes.DATEONLY,
      allowNull: false,
    },
    address: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    city: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    state: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    pincode: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    username: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    department: {
      type: DataTypes.ARRAY(DataTypes.STRING),
      allowNull: false,
    },
    authdiscper:{
      type: DataTypes.INTEGER,
      defaultValue:0,
    },
    discountauthorization:{
      type: DataTypes.BOOLEAN,
      defaultValue:false,
    },
    role: {
      type: DataTypes.ARRAY(DataTypes.STRING),
      allowNull: true,
    },
    isactive: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: true,
    },
    created_by: {
      type: DataTypes.STRING, // or FK to admin user
      allowNull: true,
    },

    image: {
      type: DataTypes.STRING, // store file path / URL
      allowNull: true,
    },
    update_by: {
      type: DataTypes.STRING,
    },

    hospitalid: {
      type: DataTypes.INTEGER,
      allowNull: true,
      references: {
        model: Hospital,
        key: "id",
      },
      onDelete: "SET NULL",
    },
    nodalid: {
      type: DataTypes.INTEGER,
      allowNull: true,
      references: {
        model: Nodal,
        key: "id",
      },
      onDelete: "SET NULL",
    },
    doctor_id: {
      type: DataTypes.INTEGER,
      allowNull: true,
      references: {
        model: Doctor,
        key: "id",
      },
      onDelete: "SET NULL",
    },
    nominee_name: {
      type: DataTypes.STRING,
    },
    nominee_contact: {
      type: DataTypes.STRING,
    },
    doc_sig: {
      type: DataTypes.STRING,
    },
    certificate: {
      type: DataTypes.STRING,
    },
    failed_attempts: {
      type: DataTypes.INTEGER,
      defaultValue: 0,
    },
    is_locked: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    locked_at:{
      type: DataTypes.DATE,
      allowNull:true,
    }
  },
  {
    timestamps: true,
    createdAt: "created_date",
    updatedAt: "update_date",
    tableName: "users",
    underscored: true,
  }
);

// Associations
// Hospital and User
User.belongsTo(Hospital, { foreignKey: "hospitalid" });
Hospital.hasMany(User, { foreignKey: "hospitalid" });
// User and Nodal
User.belongsTo(Nodal, { foreignKey: "nodalid" });
Nodal.hasMany(User, { foreignKey: "nodalid" });
// User and Doctor
Doctor.hasOne(User, { foreignKey: "doctor_id" });
User.belongsTo(Doctor, { foreignKey: "doctor_id" });
// User and Role
// User.belongsTo(RoleType, { foreignKey: "role", as: "roleType" });
// RoleType.hasMany(User, { foreignKey: "role", as: "users" });

module.exports = User;
