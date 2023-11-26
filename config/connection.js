const mysql = require('mysql');

const con = mysql.createConnection({
    host: "localhost", // Replace with your database host
    user: "root",      // Replace with your database username
    password: "root",  // Replace with your database password
    database: "node"   // Replace with your database name
});

con.connect((err) => {
    if (err) {
        console.error('Database connection error:', err);
    } else {
        console.log('Connected to the database');
    }
});

module.exports = con;
