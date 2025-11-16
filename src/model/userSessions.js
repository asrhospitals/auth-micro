const { DataTypes } = require("sequelize");
const sequelize = require("../db/dbConfig");
const User=require("../model/userModel");

const Session = sequelize.define(
  "Session",
  {
    session_id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
      allowNull: false,
    },
    user_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: User,
        key: "user_id", 
      },
      onUpdate: "CASCADE",
      onDelete: "CASCADE",
    },
    login_time: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW,
    },
    logout_time: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    ip_address: {
      type: DataTypes.STRING(45),
      allowNull: true,
      comment: "Optional: IP address of the user at login",
    },
    user_agent_info: {
      type: DataTypes.STRING,
      allowNull: true,
      comment: "Raw User-Agent string containing browser and OS details",
    },
  },
  {
    tableName: "user_sessions",
    timestamps: true, // Uses createdAt (for login_time) and updatedAt
    updatedAt: false, // We will manually manage logout_time
  }
);

// Define Association: A Session belongs to a User
Session.belongsTo(User, { foreignKey: "user_id",as:"users" });
User.hasMany(Session, { foreignKey: "user_id" });

module.exports = Session;
