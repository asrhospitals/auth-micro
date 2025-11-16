const { DataTypes } = require("sequelize");
const sequalize = require("../db/dbConfig");

const Hospital = sequalize.define(
  "hospital",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    hospitalname: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    address: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    city: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    district: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    pin: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
    states: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    phoneno: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    cntprsn: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    cntprsnmob: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    isactive: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
    },
    hospital_type_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: "hospitaltypes",
        key: "id",
      },
    },
  },
  {
    timestamps: false,
  }
);

module.exports = Hospital;
