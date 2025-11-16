const { Sequelize } = require("sequelize");

// Stagging Database Connection
const sequelize = new Sequelize("labdb", "labuser", "labpassword", {
  host: "213.210.37.3",
  dialect: "postgres",
  port: 5432,
});

module.exports = sequelize;
