const jsonServer = require('json-server');
const auth = require('json-server-auth');
const path = require('path');

const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();
// Explicitly load the rules file
const rule_contents = require(path.join(__dirname, 'my-auth-rules.json'));
console.log("Loading custom routes:", Object.keys(rule_contents));
const rules = auth.rewriter(rule_contents);

server.db = router.db

server.use(middlewares); // Loads defaults first (Logger, CORS, JSON parser)
server.use(jsonServer.bodyParser) // necessary to parse JSON request bodies

// Note:
// This Mocking Middleware "kill switch" must be
// (1) AFTER the middlewares, and 
// (2) BEFORE the auth and router
server.use((req, res, next) => {
  if (req.header('X-Simulate-503') === 'true') {
    // The json-server Logger sees the status code I set and outputs that to the console, with the method!
    // this is retrofit friendly; the json below appears in the response.errorBody() when response.isSuccessful is false
    return res.status(503).send({ code: 503, error: "Service Unavailable: Server is under maintenance"});
  }
  // Otherwise proceed as normal
  next();
});

// Note:
// This Mocking Middleware "kill switch" must be
// (1) AFTER the middlewares, and
// (2) BEFORE the auth and router
server.use((req, res, next) => {
  if (req.header('trigger-error') === 'true') {
    // The json-server Logger sees the status code I set and outputs that to the console, with the method!
    // this is retrofit friendly; the json below appears in the response.errorBody() when response.isSuccessful is false
    return res.status(500).send({ code: 500, error: "Internal Server Error: Something went wrong"});
  }
  // Otherwise proceed as normal
  next();
});

// This Mocking Middleware is a test scenario
// when any endpoint returns 401 forbidden
// to simulate an expired access token.

// 2. Proactive Interceptor: Still use a small middleware to catch the 401 scenario
// because this applies globally to your database routes
// (like /roles, /permissions, /messages, /bulletins)
server.use((req, res, next) => {
  if (req.headers['x-test-scenario'] === 'expired-token') {
    // The json-server Logger sees the status code I set and outputs that to the console, with the method!
    // this is retrofit friendly; the json below appears in the response.errorBody() when response.isSuccessful is false
    return res.status(401).json({ code: 401, error: "Token expired" });
  }
  next();
});

// This Mocking Middleware customizes login response
// so that the Android app can get the refresh token
// to be used in Authenticator.

// --- 1. INTERCEPT LOGIN TO ADD REFRESH TOKEN ---
// --- MANUALLY HANDLE LOGIN TO INJECT REFRESH TOKEN ---
// The server.js handles the login logic MANUALLY right inside our custom middleware.
server.post(['/login', '/auth/login'], (req, res) => {

  console.log('Custom login handler triggered');
  const { email, password } = req.body;

  // 1. Fetch the user by email ONLY
  const db = router.db;
  const user = db.get('users').find({ email: email }).value();

  // 2. If the user exists, use bcrypt to verify the password
  const bcrypt = require('bcryptjs');
  const isPasswordValid = user ? bcrypt.compareSync(password, user.password) : false;

  // 3. If user doesn't exist OR password doesn't match, reject them
  if (!user || !isPasswordValid) {
    console.log('Login failed: Invalid email or password');
    return res.status(400).json({ code: 400, error: "Incorrect email or password" });
  }

  console.log('Login successful for user ID:', user.id);

  const jwt = require('jsonwebtoken');
  const JWT_SECRET_KEY = 'SECRET_KEY'; // json-server-auth default secret
  const JWT_REFRESH_SECRET_KEY = 'REFRESH_SUPER_SECRET_KEY'; // json-server-auth default secret
  
  // 3. Generate the compliant access token (using standard jwt).
  //    Allow 1 hour of access.
  const accessToken = jwt.sign(
    { id: user.id, sub: String(user.id) },
    JWT_SECRET_KEY,
    { expiresIn: '1h' }
  );

  // 4. Generate the compliant refresh token (using standard jwt).
  //    Allow 3 days of refresh access.
  //    A value between 24h and 7d is reasonable.
  const refreshToken = jwt.sign(
    { id: user.id, sub: String(user.id) },
    JWT_REFRESH_SECRET_KEY,
    { expiresIn: '3d' }
  );

  // 5. Send the combined response cleanly
  console.log('Sending token bundle back to client');
  
  // Clone user object and remove password before sending to client for security
  const { password: _, ...userWithoutPassword } = user;

  return res.json({
    accessToken: accessToken,
    refreshToken: refreshToken,
    user: userWithoutPassword
  });
});

// This Mocking Middleware simulates the refresh scenario.
// It does both the happy path and the sad path (403)
// of using a refresh token to get a new access token.

// 3. EXPLICIT POST ROUTE: Dataless, action-based refresh endpoint
server.post('/auth/refresh', (req, res) => {

  console.log('the POST refresh')

  const refreshScenario = req.headers['x-refresh-scenario'];
  
  // Test case: Force a 403
  if (refreshScenario === 'expired-refresh-token') {
    return res.status(403).json({ code: 403, error: "Refresh token expired. Force logout." });
  }

  const { refreshToken } = req.body;
  const jwt = require('jsonwebtoken');
  const JWT_SECRET_KEY = 'SECRET_KEY'; // json-server-auth default secret
  const JWT_REFRESH_SECRET_KEY = 'REFRESH_SUPER_SECRET_KEY'; // json-server-auth default secret

  // 1. Verify and Decode the Refresh Token
  try {
    // This line checks BOTH the signature and the expiration date automatically!
    const decodedRefresh = jwt.verify(refreshToken, JWT_REFRESH_SECRET_KEY);

    // If it reaches this line, the token is 100% valid and NOT expired!
    console.log('Decoded refresh token payload', decodedRefresh)

    // Extract the userId that was baked into the refresh token payload
    const userId = decodedRefresh.id;

    // 2. Generate the new short-lived access token
    const newAccessToken = jwt.sign(
      { id: userId, sub: String(userId) },
      JWT_SECRET_KEY,
      { expiresIn: '1h' }
    );

    // Normal case: Success
    // The 'return' is unnecessary since this is the last line in the middleware
    res.json({
      accessToken: newAccessToken
    });


  } catch (error) {
    // 3. Catch the expiration or tampering error
    console.log('Refresh token verification failed', error.message);

    // jsonwebtoken explicitly sets error.name to 'TokenExpiredError' if it is expired
    if (error.name === 'TokenExpiredError') {
      return res.status(403).json({
        code: 403,
        error: "Refresh token expired. Force logout."
      });
    }

    // Handle other errors (like a fake/tampered token
    return res.status(403).json({
      code: 403,
      error: "Invalid refresh token"
    });
  }

});

server.use(rules);
server.use(auth);
server.use(router);

server.listen(4000, () => {
  console.log('my custom json server instance is running on http://localhost:4000')
});
