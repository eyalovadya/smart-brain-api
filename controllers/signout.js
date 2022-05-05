const jwt = require("jsonwebtoken");
const redis = require("redis");

// Setup Redis:
const redisClient = redis.createClient({ url: process.env.REDIS_URL });

const deleteToken = (token) => {
  return Promise.resolve(redisClient.del(token));
};

const handleSignout = (req, res) => {
  const { authorization } = req.headers;

  return deleteToken(authorization)
    .then(() => res.json("success"))
    .catch((err) => res.status(400).json(err));
};

module.exports = {
  handleSignout,
};
