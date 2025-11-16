require("dotenv").config();
const express = require("express");
const app = express();
const cors = require("cors");
const PORT = process.env.PORT || 3007;
const sequelize = require("./src/db/dbConfig");
const AuthRoutes=require("./src/routes/routes");
const {checkAdmin}=require("./src/controller/authenticationController");
const CertificateUploader=require("./src/controller/certificateUploader");
const ProfilePicture= require("./src/controller/profileImageUploader");

app.use(express.json());
app.use(cors());


// Routes
app.use("/lims",AuthRoutes);
// Image Routes
app.use("/lims/certificate", CertificateUploader);
app.use("/lims/profile", ProfilePicture);

const server = async () => {
  try {
    await sequelize.authenticate();
    await checkAdmin();
    // await sequelize.sync();
    console.log("Database connection established successfully.");
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  } catch (error) {
    console.error(`Unable to connect to the database ${error}`);
    process.exit(1);
  }
};

server();
