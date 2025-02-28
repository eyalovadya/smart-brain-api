BEGIN TRANSACTION;

CREATE TABLE users (
  id serial PRIMARY KEY,
  name VARCHAR(100),
  email TEXT UNIQUE NOT NULL,
  entries BIGINT DEFAULT 0,
  joined timestamp NOT NULL,
  age INT NULL,
  pet VARCHAR(100) NULL
);

COMMIT;