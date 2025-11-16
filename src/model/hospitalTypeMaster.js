const { DataTypes } = require("sequelize");
const sequelize = require("../db/dbConfig");

const HospipatlType = sequelize.define("hospitaltype", {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  hsptltype: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isAlpha: true,
    },
  },
  hsptldsc: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  isactive: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
  },
},{timestamps:false});

module.exports = HospipatlType;
