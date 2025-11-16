const { DataTypes } = require('sequelize');
const sequialize =require("../db/dbConfig");


const Nodal=sequialize.define('nodal',{
    id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true,
      },
    nodalname:{
        type:DataTypes.STRING,
        allowNull:false,
        unique: true
    },
    motherlab:{
        type:DataTypes.BOOLEAN,
        allowNull:false
    },
    isactive:{
        type:DataTypes.BOOLEAN,
        allowNull:false
    }
},{timestamps: false});

module.exports=Nodal;