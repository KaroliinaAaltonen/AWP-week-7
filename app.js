const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = 3000;

app.use(bodyParser.json());
app.use(cookieParser());
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
}));

// list of registered users
const users = [];

// task 5: list of todos
const todos = [];

// Task 4: Redirecting already logged in user
// Express cares about the order of functions so this didn't work because it was underneath authenticateUser
const alreadyLoggedIn = (req, res, next) => {
  if (!req.session.user){
      // if user is not logged in then nevermind
      next();
  }else {
      // redirecting already logged in user
      res.redirect('/');
  }
};

// Task 3: Check if user is authenticated or not
const authenticateUser = (req, res, next) => {
    if(req.session.user){
        next();
    }else{
        res.status(401).json({error: 'Unauthorized user'});
    }
};


// Task 3: GET route for protected resource
app.get('/api/secret', authenticateUser, (req, res) => {
    // successful status for authenticated user
    res.status(200).json({ message: 'Secret stuff revealed'});
});

// POST route for user registration (+ Task 4 alreadyLoggedIn option)
app.post('/api/user/register', alreadyLoggedIn, (req, res) => {
  const { username, password } = req.body;

  // Checks if the username already exists
  const existingUser = users.find(user => user.username === username);
  if (existingUser) {
    return res.status(400).json({ error: 'Username already exists.' });
  }

  // Generates a unique id for the new user
  const userId = Date.now();

  // Hashes the password with bcrypt
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      return res.status(500).json({ error: 'Error hashing the password.' });
    }

    // Creates a new User Object
    const newUser = {
      id: userId,
      username: username,
      password: hashedPassword,
    };

    // Adds the user to the list of registered users
    users.push(newUser);

    // Returns the created user
    res.json(newUser);
  });
});

// Task 2: checking username and password (+ Task 4 alreadyLoggedIn option)
app.post('/api/user/login', alreadyLoggedIn, (req, res) =>{
    const {username, password } = req.body;

    //Searching by username
    const user = users.find(user => user.username === username);

    // Compare username and password to existing data
    if(user && bcrypt.compareSync(password, user.password)){
        req.session.user = user;

        //if login is successful, respond, and set session cookie
        res.status(200).json({message: 'OK'});
    }else{
        //else invalid credentials
        res.status(401).json({error: 'Not OK'});
    }
})

// Task 5: POST route for creating todos
app.post('/api/todos', authenticateUser, (req, res) => {
    const userId = req.session.user.id;
    const {todo} = req.body;
    // search for pre-existing todo or create a new one
    let userTodo = todos.find(user => user.id === userId);
    if (!userTodo){
        userTodo = {
            id: userId,
            todos: [],
        };
        todos.push(userTodo);
    }

    //Adding the new todo to the user's todo list
    userTodo.todos.push(todo);
    //respond updates todo object
    res.json(userTodo);
});

//Task 5: GET route for todo lists
app.get('/api/todos/list', (req, res) => {
  res.json(todos);
})

// GET route for the list of registered users
app.get('/api/user/list', (req, res) => {
  // Returns the list of users
  res.json(users);
});

// Starting server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
