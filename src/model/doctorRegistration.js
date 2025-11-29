const { DataTypes } = require("sequelize");
const sequilize =  require("../db/dbConfig");


const Doctor = sequilize.define(
  "doctor",
  {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
    },
    dname: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    ddob: {
      type: DataTypes.DATEONLY,
    },
    daadhar:{
      type: DataTypes.STRING,
    },
    dqlf: {
      type: DataTypes.ARRAY(DataTypes.STRING),
    },
    dspclty: {
      type: DataTypes.ARRAY(DataTypes.STRING), 
    },
    dnb:{
      type: DataTypes.BOOLEAN,
      allowNull:true
    },
    ddpt: {
      type: DataTypes.STRING,  
    },
    assign_ddpt:{
       type: DataTypes.ARRAY(DataTypes.STRING),
    },
    dregno: {
      type: DataTypes.STRING,
    },
    dregcnl: {
      type: DataTypes.STRING,
    },
    dcnt: {
      type: DataTypes.STRING,
    },
    dwhtsap: {
      type: DataTypes.STRING,
    },
    demail: {
      type: DataTypes.STRING,
    },
    dphoto: {
      type: DataTypes.STRING,
    },
    dcrtf: {
      type: DataTypes.STRING,
    },
    dditsig: {
      type: DataTypes.STRING,
    },
    dcertificate:{
      type: DataTypes.STRING,
    },
    dindemnity:{
      type: DataTypes.BOOLEAN,
      allowNull:true
    },
    hospitalid:{
      type: DataTypes.INTEGER,
    },
    nodalid:{
      type: DataTypes.INTEGER,
    },
    dstatus: {
      type: DataTypes.ENUM,
      values: ["active", "pending","rejected"],
      defaultValue: "pending",
    },
  },
  { timestamps: false }
);

module.exports = Doctor;
