const con = require('../config/connection.js');

// Define the route handler function to retrieve data
const getData = (req, res) => {
    con.query("SELECT * FROM users", (err, result) => {
        if (err) {
            console.error(err);
            res.status(500).json({ error: 'Database error' });
        } else {
            res.json(result);
        }
    });
};

const postData = (req, res) => {
    const { first_name, last_name, id, number, dummy } = req.body;
    const sql = "INSERT INTO users (first_name, last_name, id, number, dummy) VALUES (?, ?, ?, ?, ?)";
    const values = [first_name, last_name, id, number, dummy];

    con.query(sql, values, (err, result) => {
        if (err) {
            console.error(err);
            res.status(500).json({ error: 'Database error' });
        } else {
            res.json({ message: 'Data inserted successfully', affectedRows: result.affectedRows });
        }
    });
};

const updateData = (req, res) => {
    const { first_name, last_name, number, dummy } = req.body;
    const id = req.params.id; // Extract id from the URL

    const sql = "UPDATE users SET first_name = ?, last_name = ?, number = ?, dummy = ? WHERE id = ?";
    const values = [first_name, last_name, number, dummy, id];

    con.query(sql, values, (err, result) => {
        if (err) {
            console.error(err);
            res.status(500).json({ error: 'Database error' });
        } else {
            res.json({ message: 'Data updated successfully', affectedRows: result.affectedRows });
        }
    });
};
const deletData = (req, res) => {
    const id = req.params.id; // Extract id from the URL
    const sql = "DELETE FROM `users` WHERE id = ?";
    const values = [id];

    con.query(sql, values, (err, result) => {
        if (err) {
            console.error(err);
            res.status(500).json({ error: 'Database error' });
        } else {
            res.json({ message: 'Data updated successfully', affectedRows: result.affectedRows });
        }
    });
};

module.exports = {
    getData,
    postData,
    updateData,
    deletData
};
