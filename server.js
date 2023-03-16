// Import required modules
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Create a new Express app
const app = express();
const port = process.env.PORT || 3000;
const mongodbUrl = process.env.Mongodb_Url;

// Connect to MongoDB
mongoose.connect(mongodbUrl, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error(err));


// Define the user schema for database
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

app.use(express.json());

// Define the signup route
app.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find the user with the given email inside databse
    const existingUser = await User.findOne({ email });

    // If the user email already exist, send the below response
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    // define the salt round
    const salt = await bcrypt.genSalt(10);
    // hase the password with bcrypt
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      email,
      password: hashedPassword,
    });

    await newUser.save();

    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find the user with the given email inside databse
    const user = await User.findOne({ email });

    // If the user email does not exist, send the error response
    if (!user) {
      return res.status(401).json({ message: 'Authentication failed' });
    }

    // Check if the enter password is matching with the database password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Authentication failed' });
    }

    // if (password != user.password) {
    //   return res.status(401).json({ message: 'Authentication failed' });
    // }

    // Generate a JWT and send it as a response
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
    res.status(200).json({ token });


  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/user', (req, res) => {
  const token = req.headers.authorization.split(' ')[1];
  // Verify the token
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    // Return the user email and password
    const email = req.body.email;
    const password = req.body.password;
    res.json({ email: email, password: password });
  });
});

// Start the server on port 3000
app.listen(port, () => console.log(`Server started on port ${port}`));