require('dotenv').config(); 
const {S3Client,PutObjectCommand}=require("@aws-sdk/client-s3");
const multer = require("multer");
const express = require("express");
const router = express.Router();
const { v4: uuidv4 } = require('uuid');




// Configure AWS S3 (or equivalent cloud storage)
const s3 = new S3Client({
    region: 'ap-south-1',
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    }
});

// Configure Multer to store files in memory
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: { fileSize: 2 * 1024 * 1024 } // 2MB limit
});


router.post('/upload-profile', upload.single('profile'),async(req,res)=>{
    try {
        
              // Handle file upload to S3 (or your preferred cloud storage)
              let fileUrl = null;
              if (req.file) {
                const fileKey = `profile/${uuidv4()}-${req.file.originalname}`;
                
                const uploadParams = {
                  Bucket: process.env.AWS_BUCKET_NAME,
                  Key: fileKey,
                  Body: req.file.buffer,
                  ContentType: req.file.mimetype,
                };
                
                // Upload to S3 using SDK v3 method
                const command = new PutObjectCommand(uploadParams);
                await s3.send(command);
                
                // Generate URL (S3 v3 doesn't return URL directly)
                fileUrl = `https://${process.env.AWS_BUCKET_NAME}.s3.${'ap-south-1'}.amazonaws.com/${fileKey}`;
                res.json({ success: true, fileUrl });
              }
    } catch (error) {
        res.status(500).json({ error: `Failed to upload image ${error}` });
    }
})

module.exports=router;