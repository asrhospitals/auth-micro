const { DataTypes } = require('sequelize');
const sequelize = require("../db/dbConfig"); // Ensure this points to your Sequelize connection

const OTP = sequelize.define('otp', {
    user_id: {
        type: DataTypes.INTEGER, // Use UUID if ObjectId-like behavior is needed
        allowNull: false,
        references: {
            model: 'users', // Replace 'users' with the name of your user table
            key: 'user_id',
        },
        onDelete: 'CASCADE', // Optional: delete OTP if user is removed
    },
    otp: {
        type: DataTypes.INTEGER,
        allowNull: false,
    },
    expiresAt: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: () => new Date(Date.now() + 5 * 60 * 1000), // Set expiration to 5 minutes ahead
    },

},{timestamps: false});

module.exports=OTP; 