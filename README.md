# Role-Based Access Control (RBAC) Full-Stack Application

A production-ready, secure full-stack Node.js/Express web application with role-based access control (RBAC), JWT authentication stored in HTTP-only cookies, MongoDB/Mongoose persistence, input sanitization, and a modern glassmorphic Tailwind CSS dark mode user interface.

## Key Features

1. **Authentication & Session Management**:
   - Separate login channels for normal **Users** and **Admins**.
   - JWT tokens signed on the server and stored in **HTTP-only, Secure SameSite=Lax cookies**.
   - Public registration page restricted to generating accounts with the `user` role only.
   - Persistent session storage and secure logout functionality.

2. **Backend Security Protections**:
   - **Double Submit Cookie CSRF Protection**: State-changing API requests (POST, PATCH, DELETE) validate standard request headers against local cookies.
   - **MongoDB Injection Sanitization**: Input sanitizer stripping query selectors (keys starting with `$`) from request body, query, and params.
   - **XSS Protection**: HTML characters escaped upon database writes; frontend uses safe DOM properties (`textContent`) for rendering.
   - **Helmet Security Headers**: Configured Content Security Policy (CSP) allowing Tailwind CSS CDN and Google Fonts.
   - **Login Rate Limiter**: Rate limit on authentication paths to prevent brute-force attacks.

3. **User Dashboard (`/dashboard`)**:
   - Displays logged-in user profile details (Full Name).
   - Lists other registered member names. Excludes sensitive info (emails, password hashes, roles, etc.) and admin account visibility.

4. **Admin Dashboard (`/admin`)**:
   - **Directory Table**: Shows all account details (Full Name, Email, Role, Created Date, Last Login, Status).
   - **Dynamic Cards**: Real-time stats on Total Users, Total Admins, Active Users, and Disabled Users.
   - **Search & Filters**: Live searching by name/email, filtering by role, and filtering by account status.
   - **Pagination**: Easy navigation with next/previous controls and indicator.
   - **Administrative Operations**:
     - Create User & Create Admin (via interactive modals).
     - Enable / Disable Account.
     - Promote User to Admin / Demote Admin to User.
     - Delete User permanently (with confirmation dialog).
     - Self-action locks (cannot delete, disable, or demote yourself).
     - Safeguard: Prevents demoting or deleting the last admin.

---

## Folder Structure

```
├── config/
│   └── env.js            # Environment validation and variables configuration
├── middleware/
│   ├── auth.js           # JWT verification and cookie parser helpers
│   ├── roles.js          # Role-based validation middleware
│   └── security.js       # CSRF, Mongo injection protection, Helmet CSP, and Rate Limiter
├── models/
│   └── User.js           # Mongoose Schema, Hooks, and Serialization methods
├── public/
│   ├── app.js            # Frontend logic, modals toggler, pagination, and API requests
│   ├── style.css         # Sleek glassmorphic dark theme stylesheet
│   ├── login.html        # User Login Page
│   ├── admin-login.html  # Admin Login Page
│   ├── signup.html       # User Signup Page
│   ├── dashboard.html    # User Dashboard Page
│   └── admin.html        # Admin Dashboard Page
├── routes/
│   ├── auth.js           # Signup, login, admin-login, logout routes
│   ├── user.js           # Profile view and active users list
│   └── admin.js          # Manage users, stats, search, pagination, and admin CRUD
├── scripts/
│   └── seed-admin.js     # CLI Admin seeding script
├── app.js                # Express app initialization & server routes mapping
├── server.js             # DB connector and app server listener
├── vercel.json           # Vercel deployment settings
├── package.json          # Dependency packages
└── README.md             # This document
```

---

## Installation & Setup Instructions

### 1. Prerequisites
- [Node.js](https://nodejs.org/) installed (v16+ recommended).
- [MongoDB](https://www.mongodb.com/) running locally (usually on `mongodb://127.0.0.1:27017`) or a connection string to a remote MongoDB Atlas cluster.

### 2. Install Dependencies
Run the command below in the project root directory:
```bash
npm install
```

### 3. Environment Configuration
Create a `.env` file in the root directory and define the variables. You can copy the structure from `.env.example`:
```env
PORT=3000
NODE_ENV=development
MONGODB_URI=mongodb://127.0.0.1:27017/rbac_app
JWT_SECRET=use-a-long-random-string-at-least-8-chars
JWT_EXPIRES_IN=1d
COOKIE_MAX_AGE_MS=86400000
```

### 4. Seed Administrative User
Create your first Admin account by executing the CLI seed script:
```bash
node scripts/seed-admin.js admin@example.com "Admin User" Password123
```
*Note: If the email already exists, the script promotes that user to the `admin` role and enables them.*

### 5. Start the Server
Start the local server:
```bash
npm start
```

Open your browser to:
- User Login: [http://localhost:3000/login](http://localhost:3000/login)
- Admin Login: [http://localhost:3000/admin-login](http://localhost:3000/admin-login)
- User Signup: [http://localhost:3000/signup](http://localhost:3000/signup)

---

## API Endpoints List

### Authentication
* **POST `/api/auth/signup`**: Creates a new user profile with the `user` role.
* **POST `/api/auth/login`**: Authenticates a standard user.
* **POST `/api/auth/admin-login`**: Authenticates an administrative user.
* **POST `/api/auth/logout`**: Clears cookies and ends the session.

### Users (Authenticated Session)
* **GET `/api/users/profile`**: Returns the logged-in user's full name.
* **GET `/api/users/list`**: Returns a list of all active registered user names.

### Admin (Admin Authorization)
* **GET `/api/admin/users`**: Retrieves paginated list of accounts with support for filters (role, status) and keyword search (name, email), including general system statistics.
* **POST `/api/admin/create-user`**: Creates a new account with the `user` role.
* **POST `/api/admin/create-admin`**: Creates a new account with the `admin` role.
* **PATCH `/api/admin/users/:id/disable`**: Disables an account.
* **PATCH `/api/admin/users/:id/enable`**: Enables an account.
* **PATCH `/api/admin/users/:id/promote`**: Promotes an account to Admin role.
* **PATCH `/api/admin/users/:id/demote`**: Demotes an account to User role.
* **DELETE `/api/admin/users/:id`**: Permanently deletes an account.
