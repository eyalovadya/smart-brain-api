const jwt = require("jsonwebtoken");
const redis = require("redis");

// Setup Redis:
const redisClient = redis.createClient({ url: process.env.REDIS_URL });

const handleSignin = (db, bcrypt, req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return Promise.reject("incorrect form submission");
  }
  return db
    .select("email", "hash")
    .from("login")
    .where("email", "=", email)
    .then((data) => {
      const isValid = bcrypt.compareSync(password, data[0].hash);
      if (isValid) {
        return db
          .select("*")
          .from("users")
          .where("email", "=", email)
          .then((user) => user[0])
          .catch((err) => Promise.reject("unable to get user"));
      } else {
        return Promise.reject("wrong credentials");
      }
    })
    .catch((err) => Promise.reject("wrong credentials"));
};

const getAuthTokenId = (req, res) => {
  const { authorization } = req.headers;
  redisClient.get(authorization, (err, reply) => {
    if (err || !reply) {
      return res.status(400).json("Unauthorized");
    }

    return res.json({ id: reply });
  });
};

const signToken = (email) => {
  const jwtPayload = { email };
  const token = jwt.sign(jwtPayload, "super-secret", { expiresIn: "2 days" });
  return token;
};

const setToken = (token, id) => {
  return Promise.resolve(redisClient.set(token, id));
};

const createSession = (user) => {
  const { email, id } = user;
  const token = signToken(email);
  return setToken(token, id)
    .then(() => ({
      success: "true",
      userId: id,
      token,
    }))
    .catch(console.log);
};

const signinAuthentication = (db, bcrypt) => (req, res) => {
  const { authorization } = req.headers;

  return authorization
    ? getAuthTokenId(req, res)
    : handleSignin(db, bcrypt, req, res)
        .then((data) => {
          const isUser = data.id && data.email;
          return isUser ? createSession(data) : Promise.reject(data);
        })
        .then((session) => res.json(session))
        .catch((err) => res.status(400).json(err));
};

module.exports = {
  signinAuthentication,
  redisClient,
  createSession,
};
