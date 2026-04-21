const jsonServer = require('json-server');
const auth = require('json-server-auth');
const path = require('path');

const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();
// Explicitly load the rules file
const rules = auth.rewriter(require(path.join(__dirname, 'my-auth-rules.json')));

server.db = router.db
server.use(middlewares); // Loads defaults first (Logger, CORS, JSON parser)

// Note:
// This Mocking Middleware "kill switch" must be
// (1) AFTER the middlewares, and 
// (2) BEFORE the auth and router
server.use((req, res, next) => {

  // Trigger a 503 if a specific header is present
  const simulate503 = req.header('X-Simulate-503');
  
  if (simulate503 === 'true') {
    // The json-server Logger sees the status code I set and outputs that to the console, with the method!
    // this is retrofit friendly; the json below appears in the response.errorBody() when response.isSuccessful is false
    return res.status(503).send({ code: 503, error: "Service Unavailable: Server is under maintenance"});
  }

  // Trigger a 500 if the url contains "fail"
  const triggerError = req.header('trigger-error');

  if (triggerError === 'true') {
    // The json-server Logger sees the status code I set and outputs that to the console, with the method!
    // this is retrofit friendly; the json below appears in the response.errorBody() when response.isSuccessful is false
    return res.status(500).send({ code: 500, error: "Internal Server Error: Something went wrong"});
  }

  // Otherwise proceed as normal
  next();
});

server.use(rules);
server.use(auth);
server.use(router);

server.listen(4000, () => {
  console.log('my custom json server instance is running on http://localhost:4000')
});
