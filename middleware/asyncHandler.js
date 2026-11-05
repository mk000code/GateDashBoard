const wrap = fn => (req, res) => fn(req, res).catch(error => {
  console.error(error);
  res.status(500).json({ error: "Server error" });
});

module.exports = wrap;
