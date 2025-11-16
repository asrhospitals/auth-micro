const { DataTypes } = require('sequelize');
const sequalize=require("../db/dbConfig");


const RoleType=sequalize.define('role',{

    id:{
        type:DataTypes.INTEGER,
        primaryKey:true,
        autoIncrement:true
    },
    roletype:{
        type:DataTypes.STRING,
        allowNull:false
    },
    roledescription:{
        type:DataTypes.STRING,
        allowNull:false
    },
    isactive:{
        type:DataTypes.BOOLEAN,
        allowNull:false
    }
       
});

module.exports=RoleType;