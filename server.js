const { app, connectDB } = require('./app');
const { validateEnv } = require('./config/env');

const PORT = process.env.PORT || 3000;

async function start() {
  // Validate required environment variables (exits process on error)
  validateEnv({ exitOnError: true });

  // Connect to persistent MongoDB
  await connectDB();

  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`User login: http://localhost:${PORT}/login`);
    console.log(`Admin login: http://localhost:${PORT}/admin-login`);
    console.log(`Signup: http://localhost:${PORT}/signup`);
  });
}

start().catch((error) => {
  console.error('Failed to start server:', error.message);
  process.exit(1);
});

