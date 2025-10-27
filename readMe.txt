User Authentication & Management Backend
A secure Node.js + Express + MongoDB backend with JWT authentication, role-based access control, and email verification. It supports registration, login with 2FA (email login code), password reset, user verification, and admin/author role management.
🚀 Features
•	User Registration with password validation
•	Login with email & password
•	2-Step Login Verification via email code (device-based)
•	JWT Authentication with HTTP-only cookies
•	Email Verification (via token link)
•	Forgot / Reset Password
•	Role-based Authorization (Admin, Author, Subscriber)
•	Email templating using Handlebars
•	Secure Password Hashing with bcrypt
•	Middleware for error handling & authentication
•	MongoDB with Mongoose models
•	Environment-based configuration with dotenv
🧱 Tech Stack
•	Backend: Node.js, Express.js
•	Database: MongoDB, Mongoose
•	Authentication: JWT, bcryptjs, cryptr
•	Email Service: Nodemailer + Handlebars templates
•	Utilities: UA-Parser-JS, dotenv, express-async-handler
•	Middleware: Custom auth & error handlers
📂 Project Structure
backend/
│
├── controller/user.js              - Handles user operations
├── model/user.js                   - User schema
├── model/token.js                  - Token schema
├── middleware/authMiddleware.js    - Protects routes
├── middleware/errorMiddleware.js   - Global error handler
├── routes/user.js                  - User API routes
├── util/index.js                   - JWT & hashing helpers
├── util/sendEmail.js               - Email sender
├── views/                          - Email templates (.handlebars)
└── server.js                       - Main entry point
📡 API Endpoints
POST /register - Register new user
POST /login - Login with password
POST /sendLoginCode/:email - Send login code
POST /loginWithCode/:email - Login via code
GET /logout - Logout
GET /getUser - Get logged-in user
PATCH /updateUser - Update user profile
DELETE /:id - Delete user (admin only)
GET /getUsers - Get all users (admin/author)
POST /upgradeUser - Change user role (admin)
POST /sendVerificationEmail - Send verification link
PATCH /verifyUser/:token - Verify email
POST /forgotPass - Send password reset link
PATCH /resetPass/:token - Reset password
PATCH /changePass - Change password
GET /loginStatus - Check user login status
📧 Email Templates
Handlebars templates located in `/views`:
- verifyEmail
- loginCode
- forgottenPass

Each template receives `{ name, link }` variables for personalization.
🧠 Security Notes
•	Uses HTTP-only cookies for JWT storage (XSS protection)
•	Enforces password strength (uppercase, lowercase, number, special char)
•	Tokens hashed before saving in DB
•	Login code encrypted with Cryptr
•	Role and verification checks protect sensitive routes
🧩 Error Handling
Global error handler (`errorMiddleware.js`) returns consistent JSON responses:
{ "message": "Error message", "stack": "Shown only in development" }
👨‍💻 Author
Pouya Behrooj
https://github.com/Pouya-lab/auth-backend
Email: pouyabh1999@gmail.com




backend/
│
├── controller/
│   └── user.js               # Handles all user operations (register, login, verify, etc.)
│
├── model/
│   ├── user.js               # User schema (Mongoose)
│   └── token.js              # Token schema (for verification, reset, login)
│
├── middleware/
│   ├── authMiddleware.js     # Protects routes, handles roles & verification
│   └── errorMiddleware.js    # Handles global errors
│
├── routes/
│   └── user.js               # Defines user API endpoints
│
├── util/
│   ├── index.js              # Helper functions (JWT & hash generator)
│   └── sendEmail.js          # Email sender with Handlebars templates
│
├── views/                    # Email templates (.handlebars)
│
├── .env                      # Environment variables (not uploaded)
├── package.json
└── server.js                 # Main server entry point
