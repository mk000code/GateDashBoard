const { MONGODB_URI, PORT } = require("./config/settings");
const mongoose = require("mongoose");
const app = require("./app");

mongoose.connect(MONGODB_URI).then(() => {
  app.listen(PORT, () => console.log("Running on http://localhost:" + PORT));
}).catch(error => {
  console.error("MongoDB connection failed:", error.message);
  process.exit(1);
});
