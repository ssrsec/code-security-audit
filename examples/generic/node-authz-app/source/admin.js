const express = require("express");

const app = express();

app.delete("/admin/users/:id", async (req, res) => {
  const userId = req.params.id;
  await deleteUser(userId);
  res.json({ ok: true });
});

async function deleteUser(userId) {
  return { deleted: userId };
}

module.exports = app;
