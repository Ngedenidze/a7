
//Nika Gedenidze a7

//load modules
const express = require('express');
const nedb = require("nedb-promises");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');


//init app and db
const app = express();
const db = nedb.create('users.jsonl');

// enable static routing to "./public" folder
app.use(express.static('public'));


// automatically decode all requests from JSON and encode all responses into JSON
app.use(express.json());


// create route to get all user records (GET /users)
//   use db.find to get the records, then send them
//   use .catch(error=>res.send({error})) to catch and send errors
app.get('/users', (req, res) => { // GET all data
  db.find({})
    .then(docs => res.send(docs))
    .catch(error => res.send({ error }));
});


// create route to get user record (POST /users/:username)
//   use db.findOne to get user record
//     if record is found, send it
//     otherwise, send {error:'Username not found.'}
//   use .catch(error=>res.send({error})) to catch and send other errors
app.post('/users/:username', async (req, res) => {

  // try catch 
  try {
    // get user information(username)
    const doc = await db.findOne({ username: req.params.username });

    // error checking - 404
    if (!doc) {
      return res.status(404).send({ error: 'Username not found.' });
    }

    // compared hash password
    const enteredPassword = req.body.password;
    const passwordMatches = bcrypt.compareSync(enteredPassword, doc.password);

    // error checking - 401
    if (!passwordMatches) {
      return res.status(401).send({ error: 'Incorrect password.' });
    }

    
    else {

      // authenticate with token
      const authenticationToken = jwt.sign({ username: req.params.username }, 'secret');
      await db.update({ username: req.params.username },
        {
          // update the token
          $set: { auth: authenticationToken }
        });

      // send token on res with user infomation
      res.send({ auth: authenticationToken, user: doc });
    }

  } catch (error) {
    return res.send({ error });
  }
});






// create route to register user (POST /users)
//   ensure all fields (username, password, email, name) are specified; if not, send {error:'Missing fields.'}
//   use findOne to check if username already exists in db
//     if username exists, send {error:'Username already exists.'}
//     otherwise,
//       use bcrypt to hash the password
//       use insertOne to add document to database
//       if all goes well, send returned document
//   use .catch(error=>res.send({error})) to catch and send other errors
app.post('/users', async (req, res) => {
  const { username, password, email, name } = req.body;

  // check if all required fields are present
  if (!username || !password || !email || !name) {
    return res.status(400).json({ error: 'Missing fields.' });
  }

  // try-catch
  try {
    const doc = await db.findOne({ username: req.body.username });
    if (doc) {
      res.status(409).send({ error: 'Username already exists.' });
    } else {
      // hash the password using bcrypt
      const hashedPassword = await bcrypt.hash(password, 2);
      // generate an authentication token
      const authenticationToken = jwt.sign({ username }, 'secret');

      // store the hashed password and authentication token in the database
      const user = { username, password: hashedPassword, email, name, auth: authenticationToken };
      const result = await db.insertOne(user);
      res.send({ user: user, ...result });
    }
  } catch (error) {
    res.send({ error });
  }
});

//Logout
app.post('/logout', async (req, res) => {
  const { username } = req.body;
  const doc = await db.findOne({ username });
  // error checking
  if (!doc) {
    return res.status(404).send({ error: 'User not found.' });
  }

  // update the user's record to remove the authentication token.
  await db.updateOne({ username }, { $unset: { auth: "" } });

  res.status(200).send({ message: 'Logged out successfully.' });
});




// create route to update user doc (PATCH /users/:username)
//   use updateOne to update document in database
//     updateOne resolves to 0 if no records were updated, or 1 if record was updated
//     if 0 records were updated, send {error:'Something went wrong.'}
//     otherwise, send {ok:true}
//   use .catch(error=>res.send({error})) to catch and send other errors
app.patch('/users/:username', async (req, res) => {
  const { username } = req.params;
  const updateData = { ...req.body };
  delete updateData.username;

  const doc = await db.findOne({ username });

  if (!doc) {
    return res.status(404).send({ error: 'User not found.' });
  }

  jwt.verify(doc.auth, 'secret', (err, user) => {
    // error checking - 403
    if (err) {
      return res.status(403).send({ error: 'Invalid authentication token.' });
    }
    
    // update method
    db.updateOne(
      { username }, // find doc with given :username
      { $set: updateData } // update it with new data
    ).then(result => {
      if (result.matchedCount == 0)
        res.status(400).send({ error: 'Something went wrong.' });
      else
        res.send({ ok: true });
    })
    .catch(error => res.send({ error }));
  });
});


// create route to delete user doc (DELETE /users/:username)
//   use deleteOne to update document in database
//     deleteOne resolves to 0 if no records were deleted, or 1 if record was deleted
//     if 0 records were deleted, send {error:'Something went wrong.'}
//     otherwise, send {ok:true}
//   use .catch(error=>res.send({error})) to catch and send other errors
app.delete('/users', async (req, res) => {
  const { username } = req.body;
  const doc = await db.findOne({ username });

  if (!doc) {
    return res.status(404).send({ error: 'User not found.' });
  }

  // authentication with token
  jwt.verify(doc.auth, 'secret', (err, user) => {
    if (err) {
      return res.status(403).send({ error: 'Invalid authentication token.' });
    } // DELETE doc for given :username
    db.deleteOne({ username }) // remove matching doc
      .then(result => {
        if (result.deletedCount == 0)
          res.status(400).send({ error: 'Something went wrong.' });
        else
          res.send({ ok: true });
      })
      .catch(error => res.send({ error }));
  });
});


// default route
app.all('*', (req, res) => { res.status(404).send('Invalid URL.') });

// start server
app.listen(3000, () => console.log("Server started on http://localhost:3000"));
