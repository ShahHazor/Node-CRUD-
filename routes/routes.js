const express = require("express");
const router = express.Router();

// Import the data retrieval function from data.js
const { getData, postData, updateData, deletData } = require("../data/data");
// const { postData } = require("../data/data");

// Define routes
router.get("/get", getData);
router.post("/post", postData);
router.patch("/update/:id", updateData);
router.patch("/delet/:id", deletData);

// Export the router
module.exports = router;
