const express = require("express");
const cors = require("cors");
const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());

// Import and use the dataRoutes module
const dataRoutes = require('./routes/routes.js');
app.use('/api', dataRoutes);

app.get("/", (req, res) => {
    res.json({ message: "Welcome to ShahBukht application." });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}.`);
});
