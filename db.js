require('dotenv').config();

const postgres = require('postgres');
const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error('DATABASE_URL is required.');
}

const sql = postgres(connectionString);

module.exports = sql;
