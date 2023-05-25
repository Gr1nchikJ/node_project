const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');

const app = express();
app.use(express.json());

mongoose.connect("mongodb://127.0.0.1:27017/myapp", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('Failed to connect to MongoDB', error);
  });

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});

const User = mongoose.model('User', userSchema);

const postSchema = new mongoose.Schema({
  title: String,
  content: String,
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  },
});

const Post = mongoose.model('Post', postSchema);

const commentSchema = new mongoose.Schema({
  content: String,
  post: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Post',
  },
});

const Comment = mongoose.model('Comment', commentSchema);

// Конфігурація Passport
passport.use(new LocalStrategy({ usernameField: 'username' }, async (username, password, done) => {
  try {
    const user = await User.findOne({ username });

    if (!user) {
      return done(null, false, { message: 'Invalid username or password' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return done(null, false, { message: 'Invalid username or password' });
    }

    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});


app.use(session({
  secret: 'secretKey',
  resave: false,
  saveUninitialized: false,
}));


app.use(passport.initialize());
app.use(passport.session());

// Реєстрація користувача
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to register user' });
  }
});

// Авторизація користувача
app.post('/login', passport.authenticate('local'), (req, res) => {
  res.status(200).json({ message: 'Authentication successful' });
});

// Перевірка авторизації
function authenticate(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  res.status(401).json({ error: 'Unauthorized' });
}

// Отримання всіх записів
app.get('/posts', authenticate, async (req, res) => {
  try {
    const posts = await Post.find({}).populate('author', 'username');
    res.json(posts);
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve posts' });
  }
});

// Створення нового запису
app.post('/posts', authenticate, async (req, res) => {
  const { title, content } = req.body;

  try {
    const post = new Post({ title, content, author: req.user._id });
    await post.save();
    res.status(201).json({ message: 'Post created successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create post' });
  }
});

// Оновлення запису
app.put('/posts/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { title, content } = req.body;

  try {
    await Post.findByIdAndUpdate(id, { title, content });
    res.json({ message: 'Post updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update post' });
  }
});

// Видалення запису
app.delete('/posts/:id', authenticate, async (req, res) => {
  const { id } = req.params;

  try {
    await Post.findByIdAndDelete(id);
    res.json({ message: 'Post deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete post' });
  }
});

app.get('/comments', authenticate, async (req, res) => {
  try {
    const comments = await Comment.find({}).populate('post', 'title');
    res.json(comments);
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve comments' });
  }
});

app.post('/comments', authenticate, async (req, res) => {
  const { content, post } = req.body;

  try {
    const comment = new Comment({ content, post });
    await comment.save();
    res.status(201).json({ message: 'Comment created successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create comment' });
  }
});

app.put('/comments/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { content } = req.body;

  try {
    await Comment.findByIdAndUpdate(id, { content });
    res.json({ message: 'Comment updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update comment' });
  }
});

app.delete('/comments/:id', authenticate, async (req, res) => {
  const { id } = req.params;

  try {
    await Comment.findByIdAndDelete(id);
    res.json({ message: 'Comment deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete comment' });
  }
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
