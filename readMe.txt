🔐 User Authentication & Management Backend
A secure Node.js + Express + MongoDB backend with JWT authentication, role-based access control, and email verification. Supports registration, login with 2FA (email login code), password reset, user verification, and admin/author role management.
🚀 Features
• User Registration with password validation
• Login with email & password
• Two-Step Login Verification via email code (device-based)
• JWT Authentication with HTTP-only cookies
• Email Verification (via token link)
• Forgot / Reset Password
• Role-based Authorization (Admin, Author, Subscriber)
• Email templating using Handlebars
• Secure Password Hashing with bcrypt
• Middleware for error handling & authentication
• MongoDB + Mongoose for schema modeling
• Environment-based configuration with dotenv
🧠 Tech Stack
Layer	Technologies
Backend	Node.js, Express.js
Database	MongoDB, Mongoose
Authentication	JWT, bcryptjs, cryptr
Email Service	Nodemailer + Handlebars templates
Utilities	UA-Parser-JS, dotenv, express-async-handler
Middleware	Custom auth & error handlers
📂 Project Structure
backend/
│
├── controller/user.js              # Handles user operations
├── model/user.js                   # User schema
├── model/token.js                  # Token schema
├── middleware/authMiddleware.js    # Protects routes
├── middleware/errorMiddleware.js   # Global error handler
├── routes/user.js                  # User API routes
├── util/index.js                   # JWT & hashing helpers
├── util/sendEmail.js               # Email sender
├── views/                          # Email templates (.handlebars)
└── server.js                       # Main entry point
⚙️ Installation & Setup
Clone the repository:

    git clone https://github.com/<your-username>/<repo-name>.git
    cd backend
Install dependencies:

    npm install
Create .env file with the following content:

    PORT=5000
    MONGO_URI=your_mongodb_connection_string
    JWT_SECRET=your_jwt_secret
    EMAIL_HOST=smtp.your-email.com
    EMAIL_USER=your_email@example.com
    EMAIL_PASS=your_email_password
    FRONTEND_URL=https://your-frontend-url.com
    CRYPTR_KEY=your_encryption_key
    NODE_ENV=development
Run the server:

    npm run backend
    # or in production
    npm start
📡 API Endpoints
POST /register - Register new user
POST /login - Login with password
POST /sendLoginCode/:email - Send login code
POST /loginWithCode/:email - Login via code
GET /logout - Logout user
GET /getUser - Get logged-in user
PATCH /updateUser - Update user profile
DELETE /:id - Delete user (admin only)
GET /getUsers - Get all users (admin/author)
POST /upgradeUser - Change user role (admin only)
POST /sendVerificationEmail - Send verification link
PATCH /verifyUser/:token - Verify user email
POST /forgotPass - Send password reset link
PATCH /resetPass/:token - Reset password
PATCH /changePass - Change password
GET /loginStatus - Check user login status
📧 Email Templates
Located in /views directory (Handlebars):
- verifyEmail
- loginCode
- forgottenPass

Each template accepts { name, link } for personalization.
🧠 Security Notes
• Uses HTTP-only cookies for JWT storage (prevents XSS attacks)
• Enforces password strength (uppercase, lowercase, number, special char)
• Tokens are hashed before saving to DB
• Login codes are encrypted with Cryptr
• Role & verification checks protect admin routes
🧩 Error Handling
Global error handler (errorMiddleware.js) ensures consistent JSON responses:

{ "message": "Error message", "stack": "Shown only in development" }
👨‍💻 Author
Pouya Behrooj
Master’s Student in Artificial Intelligence @ JKU Linz
GitHub: https://github.com/pouya-lab
Email: pouyabh1999@gmail.com

