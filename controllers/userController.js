const { User, users } = require("../models/Users");

exports.getUsers = (req, res) => {
    res.json(users);
  };
  
  exports.createUser = (req, res) => {
    const { name, email } = req.body;
    if (!name || !email) return res.status(400).json({ error: "Faltan datos" });
  
    const newUser = new User(name, email);
    users.push(newUser);
    res.status(201).json(newUser);
  };

