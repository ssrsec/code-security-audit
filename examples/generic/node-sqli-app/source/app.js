const express = require("express");
const db = require("./db");

const app = express();

app.get("/orders", async (req, res) => {
  const userId = req.query.userId;
  const sql = "SELECT id, total FROM orders WHERE user_id = '" + userId + "'";
  const rows = await db.query(sql);
  res.json(rows);
});

module.exports = app;
