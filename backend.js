// backend_moderator.js
require('dotenv').config();
const express = require('express');
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, PutCommand, GetCommand, ScanCommand, QueryCommand, UpdateCommand, BatchGetCommand, DeleteCommand, BatchWriteCommand } = require("@aws-sdk/lib-dynamodb");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const multer = require('multer');
const pdf = require('pdf-parse');
const fetch = require('node-fetch');
const cloudinary = require('cloudinary').v2;
const { RekognitionClient, CompareFacesCommand } = require("@aws-sdk/client-rekognition");
const crypto = require('crypto');
const SibApiV3Sdk = require('sib-api-v3-sdk');
const { Resend } = require('resend');

const ZOOM_ACCOUNT_ID = process.env.ZOOM_ACCOUNT_ID || 'bq5-fIbESBONjaZAr184uA';
const ZOOM_CLIENT_ID = process.env.ZOOM_CLIENT_ID || 'CXxbks94RlmD_90vofVqg';
const ZOOM_CLIENT_SECRET = process.env.ZOOM_CLIENT_SECRET || 'XXoYPmG5z8rSf1J6Fov7iXSminmBRuO9';


// --- INITIALIZATION ---
const app = express();
const PORT = 3000;
const JWT_SECRET = 'your-super-secret-key-for-jwt-in-production';

// --- AWS DYNAMODB CLIENT SETUP ---
const client = new DynamoDBClient({
    region: 'ap-south-1',
    credentials: {
        accessKeyId: 'AKIATCKAN7T2GJJYYJSH',
        secretAccessKey: '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'
    }
});
const docClient = DynamoDBDocumentClient.from(client);

// --- NODEMAILER TRANSPORTER SETUP ---
let defaultClient = SibApiV3Sdk.ApiClient.instance;

// Configure API key authorization: api-key
let apiKey = defaultClient.authentications['api-key'];
// IMPORTANT: Store this in an environment variable (e.g., BREVO_API_KEY) on Render
const resend = new Resend(process.env.RESEND_API_KEY || 're_uJrbJkZT_DNuYt2VNVKhYmgCxNqJwyjyL');

async function sendEmailWithResend(mailOptions) {
    try {
        await resend.emails.send({
            // IMPORTANT: You must verify your domain (testify-lac.com) with Resend
            // to use your own 'from' address. Once verified, you can use something like:
            // from: 'TESTIFY <notifications@testify-lac.com>',
            from: 'TESTIFY <onboarding@resend.dev>',
            to: mailOptions.to,
            subject: mailOptions.subject,
            html: mailOptions.html,
        });
        console.log(`Email sent successfully to ${mailOptions.to} with Resend`);
    } catch (error) {
        console.error(`Error sending email with Resend to ${mailOptions.to}:`, error);
    }
}


// --- CLOUDINARY CONFIG ---
cloudinary.config({
  cloud_name: 'dpz44zf0z',
  api_key: '939929349547989',
  api_secret: '7mwxyaqe-tvtilgyek2oR7lTkr8'
});
const upload = multer({ storage: multer.memoryStorage() });

// --- AWS REKOGNITION CLIENT SETUP ---
const rekognitionClient = new RekognitionClient({
    region: 'ap-south-1',
    credentials: {
        accessKeyId: 'AKIAVEP3EDM5MKMROQRB',
        secretAccessKey: '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'
    }
});


app.use(cors());
app.use(express.json({ limit: '10mb' }));
// app.use(express.static('public'));
// app.use('/moderator', express.static(path.join(__dirname, 'public/moderator')));

app.get('/', (req, res) => res.redirect('/welcome'));
app.get('/welcome', (req, res) => res.sendFile(path.join(__dirname, 'public', 'welcome.html')));
app.get('/about', (req, res) => res.sendFile(path.join(__dirname, 'public', 'about.html')));
app.get('/apply', (req, res) => res.sendFile(path.join(__dirname, 'public', 'apply.html')));
app.get('/careers', (req, res) => res.sendFile(path.join(__dirname, 'public', 'careers.html')));
app.get('/contact', (req, res) => res.sendFile(path.join(__dirname, 'public', 'contact.html')));
app.get('/detailed-view', (req, res) => res.sendFile(path.join(__dirname, 'public', 'detailed-view.html')));
app.get('/EduDevelopers', (req, res) => res.sendFile(path.join(__dirname, 'public', 'EduDevelopers.html')));
app.get('/features', (req, res) => res.sendFile(path.join(__dirname, 'public', 'features.html')));
app.get('/forgot-password', (req, res) => res.sendFile(path.join(__dirname, 'public', 'forgot-password.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/my-applications', (req, res) => res.sendFile(path.join(__dirname, 'public', 'my-applications.html')));
app.get('/reset-password', (req, res) => res.sendFile(path.join(__dirname, 'public', 'reset-password.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));
app.get('/T&C', (req, res) => res.sendFile(path.join(__dirname, 'public', 'T&C.html')));
app.get('/verify-certificate', (req, res) => res.sendFile(path.join(__dirname, 'public', 'verify-certificate.html')));

// --- Student Page Routes ---
app.get('/student/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'dashboard.html')));
app.get('/student/cognizant-cloud', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'cognizant-cloud.html')));
app.get('/student/cognizant-cloud-quiz', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'cognizant-cloud-quiz.html')));
app.get('/student/compiler', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'compiler.html')));
app.get('/student/contests', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'contests.html')));
app.get('/student/fullscreen-test', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'fullscreen-test.html')));
app.get('/student/interview-complete', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'interview-complete.html')));
app.get('/student/interview-dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'interview-dashboard.html')));
app.get('/student/interview-page', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'interview-page.html')));
app.get('/student/join-meeting', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'join-meeting.html')));
app.get('/student/my-certificates', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'my-certificates.html')));
app.get('/student/my-courses', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'my-courses.html')));
app.get('/student/practicetest', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'practicetest.html')));
app.get('/student/sql-compiler', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'sql-compiler.html')));
app.get('/student/profile', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'student-profile.html')));
app.get('/student/take-coding-contest', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'take-coding-contest.html')));
app.get('/student/take-test', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'take-test.html')));
app.get('/student/test-history', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'test-history.html')));
app.get('/student/Test', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'Test.html')));
app.get('/student/view-certificate', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'view-certificate.html')));
app.get('/student/view-course', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'view-course.html')));

// --- Admin Page Routes ---
app.get('/admin/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'dashboard.html')));
app.get('/admin/add-college', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'add-college.html')));
app.get('/admin/add-department', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'add-department.html')));
app.get('/admin/add-features', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'add-features.html')));
app.get('/admin/add-problems', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'add-problems.html')));
app.get('/admin/admin-impact', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'admin-impact.html')));
app.get('/admin/admin-students', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'admin-students.html')));
app.get('/admin/admin-interview-dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'admin-interview-dashboard.html')));
app.get('/admin/assign-course', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'assign-course.html')));
app.get('/admin/assign-practicetest', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'assign-practicetest.html')));
app.get('/admin/assign-test', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'assign-test.html')));
app.get('/admin/assignment-report', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'assignment-report.html')));
app.get('/admin/code-sections', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'code-sections.html')));
app.get('/admin/compiler-scores', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'compiler-scores.html')));
app.get('/admin/contest-submissions', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'contest-submissions.html')));
app.get('/admin/course-progress', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'course-progress.html')));
app.get('/admin/course-report', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'course-report.html')));
app.get('/admin/create-contest', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'create-contest.html')));
app.get('/admin/create-course', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'create-course.html')));
app.get('/admin/create-practicetest', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'create-practicetest.html')));
app.get('/admin/create-test', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'create-test.html')));
app.get('/admin/FSTest', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'FSTest.html')));
app.get('/admin/interview-report', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'interview-report.html')));
app.get('/admin/issue-certificates', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'issue-certificates.html')));
app.get('/admin/issue-course-certificates', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'issue-course-certificates.html')));
app.get('/admin/manage-jobs', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'manage-jobs.html')));
app.get('/admin/manage-moderator', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'manage-moderator.html')));
app.get('/admin/modify-course', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'modify-course.html')));
app.get('/admin/modify-fullscreen-test', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'modify-fullscreen-test.html')));
app.get('/admin/modify-test', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'modify-test.html')));
app.get('/admin/report', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'report.html')));
app.get('/admin/schedule-meeting', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'schedule-meeting.html')));
app.get('/admin/scheduled-meetings', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'scheduled-meetings.html')));
app.get('/admin/sql-scores', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'sql-scores.html')));
app.get('/admin/sql-sections', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'sql-sections.html')));
app.get('/admin/sql', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'sql.html')));
app.get('/admin/test-history', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'test-history.html')));
app.get('/admin/un-assign', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'un-assign.html')));
app.get('/admin/view-all-certificates', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'view-all-certificates.html')));
app.get('/admin/view-applications', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'view-applications.html')));
app.get('/admin/view-certificate', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'view-certificate.html')));
app.get('/admin/view-fullscreen-results', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'view-fullscreen-results.html')));

app.use(express.static('public'));
app.use('/moderator', express.static(path.join(__dirname, 'public/moderator')));


// =================================================================
// --- PERMANENT FIX FOR SERVING ZOOM SDK LOCALLY ---
// This line serves the files from the package you installed with NPM.
// It correctly points to the '@zoom/meetingsdk' directory.
// =================================================================


const authMiddleware = async (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user;

        const { Item } = await docClient.send(new GetCommand({
            TableName: "TestifyUsers",
            Key: { email: req.user.email }
        }));

        if (!Item) {
            return res.status(404).json({ message: 'User not found.' });
        }

        if (Item.isBlocked) {
            return res.status(403).json({ message: 'Your account has been blocked by the administrator.' });
        }

        if (Item.role === 'Moderator') {
            req.user.assignedColleges = Item.assignedColleges || [];
        }


        next();
    } catch (e) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

// const authMiddleware = async (req, res, next) => {
//     const token = req.header('x-auth-token');
//     if (!token) {
//         return res.status(401).json({ message: 'No token, authorization denied' });
//     }
//     try {
//         const decoded = jwt.verify(token, JWT_SECRET);
//         req.user = decoded.user;

//         const { Item } = await docClient.send(new GetCommand({
//             TableName: "TestifyUsers",
//             Key: { email: req.user.email }
//         }));

//         if (!Item) {
//             return res.status(404).json({ message: 'User not found.' });
//         }

//         if (Item.isBlocked) {
//             return res.status(403).json({ message: 'Your account has been blocked by the administrator.' });
//         }

//         req.user.fullName = Item.fullName; // Add fullName to req.user
//         req.user.college = Item.college; // Add college to req.user

//         if (Item.role === 'Moderator') {
//             req.user.assignedColleges = Item.assignedColleges || [];
//         }

//         next();
//     } catch (e) {
//         res.status(401).json({ message: 'Token is not valid' });
//     }
// };

// const adminOrModeratorAuth = (req, res, next) => {
//     if (req.user.role !== 'Admin' && req.user.role !== 'Moderator') {
//         return res.status(403).json({ message: 'Access denied.' });
//     }
//     next();
// };



// =================================================================
// --- OTP IMPLEMENTATION ---
// =================================================================
// In-memory store for OTPs. In a real application, use a database with TTL.
// const otpStore = {};

// // NEW ENDPOINT: Send OTP to user's email
// app.post('/api/send-otp', async (req, res) => {
//     const { email } = req.body;
//     if (!email) {
//         return res.status(400).json({ message: 'Email is required.' });
//     }

//     try {
//         const existingUser = await docClient.send(new GetCommand({ TableName: "TestifyUsers", Key: { email: email.toLowerCase() } }));
//         if (existingUser.Item) {
//             return res.status(400).json({ message: 'User with this email already exists.' });
//         }

//         const otp = Math.floor(100000 + Math.random() * 900000).toString();
//         const expirationTime = Date.now() + 5 * 60 * 1000; // 5 minutes from now

//         otpStore[email.toLowerCase()] = { otp, expirationTime };
//         console.log(`Generated OTP for ${email}: ${otp}`);

//         const mailOptions = {
//     from: '"TESTIFY" <testifylearning.help@gmail.com>',
//     to: email,
//     subject: 'TESTIFY Account Verification',
//     html: `<!DOCTYPE html>
// <html lang="en">
// <head>
//     <meta charset="UTF-8" />
//     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
//     <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
//     <title>Account Verification</title>
//     <style>
//         @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap');
//         body { font-family: 'Poppins', Arial, sans-serif; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }
//         a { text-decoration: none; }
//         @media screen and (max-width: 600px) {
//             .content-width {
//                 width: 90% !important;
//             }
//         }
//     </style>
// </head>
// <body style="background-color: #f3f4f6; margin: 0; padding: 0;">
//     <!-- Preheader text for inbox preview -->
//     <span style="display:none;font-size:1px;color:#ffffff;line-height:1px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;">
//         Your verification code is here.
//     </span>
//     <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #f3f4f6;">
//         <tr>
//             <td align="center" style="padding: 40px 20px;">
//                 <!-- Main Card -->
//                 <table class="content-width" width="600" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #ffffff; border-radius: 12px; box-shadow: 0 10px 30px -10px rgba(0,0,0,0.1);">
//                     <!-- Header -->
//                     <tr>
//                         <td align="center" style="padding: 30px 40px 20px; border-bottom: 1px solid #e5e7eb;">
//                             <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1756037774/Gemini_Generated_Image_eu0ib0eu0ib0eu0i_z0amjh.png" 
//                                  alt="Testify Logo" style="height: 50px; width: auto;">
//                         </td>
//                     </tr>
                    
//                     <!-- Content Body -->
//                     <tr>
//                         <td align="center" style="padding: 40px; text-align: center;">
//                              <h1 style="font-family: 'Poppins', Arial, sans-serif; font-size: 26px; font-weight: 700; color: #111827; margin: 0 0 15px;">Verify Your Account</h1>
//                              <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 16px; color: #4b5563; margin: 0 0 30px; line-height: 1.7;">
//                                  Here is your One-Time Password (OTP) to complete your account creation.
//                              </p>
//                              <div style="background-color: #f3f4f6; border-radius: 8px; padding: 20px 25px; display: inline-block;">
//                                  <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 32px; font-weight: 700; color: #111827; margin: 0; letter-spacing: 5px;">
//                                      ${otp}
//                                  </p>
//                              </div>
//                              <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 14px; color: #6b7280; margin: 30px 0 0;">
//                                  This OTP is valid for 5 minutes. For your security, please do not share it with anyone.
//                              </p>
//                         </td>
//                     </tr>
                    
//                     <!-- Footer -->
//                     <tr>
//                         <td align="center" style="padding: 30px 40px; background-color: #f9fafb; border-top: 1px solid #e5e7eb; border-radius: 0 0 12px 12px;">
//                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0 0 8px;">
//                                 &copy; ${new Date().getFullYear()} TESTIFY. All rights reserved.
//                             </p>
//                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0;">
//                                 Houston, TX, USA | <a href="mailto:testifylearning.help@gmail.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
//                             </p>
//                         </td>
//                     </tr>
//                 </table>
//             </td>
//         </tr>
//     </table>
// </body>
// </html>`
// };


//        await sendEmailWithResend(mailOptions);

//         res.status(200).json({ message: 'OTP sent successfully. Please check your email.' });
//     } catch (error) {
//         console.error("Send OTP Error:", error);
//         res.status(500).json({ message: 'Server error sending OTP. Please try again.' });
//     }
// });

const otpStore = {};

app.post('/api/send-otp', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ message: 'Email is required.' });
    }

    try {
        const existingUser = await docClient.send(new GetCommand({ TableName: "TestifyUsers", Key: { email: email.toLowerCase() } }));
        if (existingUser.Item) {
            return res.status(400).json({ message: 'User with this email already exists.' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expirationTime = Date.now() + 5 * 60 * 1000; // 5 minutes
        const verificationToken = uuidv4();

        otpStore[email.toLowerCase()] = { otp, expirationTime, verificationToken };
        console.log(`Generated OTP for ${email}: ${otp}`);

        // Construct the verification link that will be opened in a new tab
        const verificationLink = `/verify-otp.html?token=${verificationToken}`;

        // Send the link back to the frontend instead of sending an email
        res.status(200).json({ 
            message: 'Verification token generated.',
            verificationLink: verificationLink 
        });

    } catch (error) {
        console.error("Send OTP Error:", error);
        res.status(500).json({ message: 'Server error generating verification code. Please try again.' });
    }
});

// Endpoint to get OTP using the secure token from the verification page
app.post('/api/get-otp-by-token', (req, res) => {
    const { token } = req.body;
    if (!token) {
        return res.status(400).json({ message: 'Verification token is missing.' });
    }

    const email = Object.keys(otpStore).find(key => otpStore[key].verificationToken === token);

    if (!email) {
        return res.status(404).json({ message: 'This verification link is invalid or has already been used.' });
    }

    const otpData = otpStore[email];

    if (Date.now() > otpData.expirationTime) {
        delete otpStore[email];
        return res.status(400).json({ message: 'This verification link has expired.' });
    }
    
    res.json({ otp: otpData.otp });
    
    // Invalidate the token after use
    delete otpStore[email];
});


// =================================================================
// --- NEW: MODERATOR MANAGEMENT ROUTES (ADMIN ONLY) ---
// =================================================================

// Create a new moderator
app.post('/api/admin/moderators', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }

    const { fullName, email, password, assignedColleges } = req.body;
    if (!fullName || !email || !password || !assignedColleges || assignedColleges.length === 0) {
        return res.status(400).json({ message: 'Please provide full name, email, password, and at least one college.' });
    }

    try {
        const existingUser = await docClient.send(new GetCommand({ TableName: "TestifyUsers", Key: { email: email.toLowerCase() } }));
        if (existingUser.Item) {
            return res.status(400).json({ message: 'User with this email already exists.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newModerator = {
            email: email.toLowerCase(),
            fullName,
            password: hashedPassword,
            role: "Moderator",
            assignedColleges,
            isBlocked: false
        };

        await docClient.send(new PutCommand({ TableName: "TestifyUsers", Item: newModerator }));
        res.status(201).json({ message: 'Moderator account created successfully!' });
    } catch (error) {
        console.error("Create Moderator Error:", error);
        res.status(500).json({ message: 'Server error during moderator creation.' });
    }
});

// Get all moderators
app.get('/api/admin/moderators', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyUsers",
            FilterExpression: "#role = :moderator",
            ExpressionAttributeNames: { "#role": "role" },
            ExpressionAttributeValues: { ":moderator": "Moderator" }
        }));
        res.json(Items.map(({ password, ...rest }) => rest));
    } catch (error) {
        console.error("Get Moderators Error:", error);
        res.status(500).json({ message: 'Server error fetching moderators.' });
    }
});

// Delete a moderator
app.delete('/api/admin/moderators/:email', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { email } = req.params;
    try {
        await docClient.send(new DeleteCommand({
            TableName: "TestifyUsers",
            Key: { email }
        }));
        res.json({ message: 'Moderator deleted successfully.' });
    } catch (error) {
        console.error("Delete Moderator Error:", error);
        res.status(500).json({ message: 'Server error deleting moderator.' });
    }
});


// =================================================================
// --- COLLEGE MANAGEMENT ROUTES ---
// =================================================================

// GET all colleges (Public for signup, but also used by admin)
app.get('/api/colleges', async (req, res) => {
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyColleges"
        }));
        Items.sort((a, b) => a.collegeName.localeCompare(b.collegeName));
        res.json(Items);
    } catch (error) {
        console.error("Get Colleges Error:", error);
        res.status(500).json({ message: 'Server error fetching colleges.' });
    }
});

// POST a new college (Admin only)
app.post('/api/colleges', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { collegeName } = req.body;
    if (!collegeName) {
        return res.status(400).json({ message: 'College name is required.' });
    }
    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: "TestifyColleges",
            Key: { collegeName }
        }));
        if (Item) {
            return res.status(400).json({ message: 'College with this name already exists.' });
        }

        await docClient.send(new PutCommand({
            TableName: "TestifyColleges",
            Item: { collegeName }
        }));
        res.status(201).json({ message: 'College added successfully.' });
    } catch (error) {
        console.error("Add College Error:", error);
        res.status(500).json({ message: 'Server error adding college.' });
    }
});

// DELETE a college (Admin only)
app.delete('/api/colleges/:collegeName', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { collegeName } = req.params;
    try {
        await docClient.send(new DeleteCommand({
            TableName: "TestifyColleges",
            Key: { collegeName }
        }));
        res.json({ message: 'College deleted successfully.' });
    } catch (error) {
        console.error("Delete College Error:", error);
        res.status(500).json({ message: 'Server error deleting college.' });
    }
});

// =================================================================
// --- DEPARTMENT MANAGEMENT ROUTES (ADMIN ONLY) [RECTIFIED] ---
// =================================================================
app.post('/api/departments', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { departmentName } = req.body;
    if (!departmentName) {
        return res.status(400).json({ message: 'Department name is required.' });
    }
    try {
        const departmentId = `department#${departmentName}`;
        const { Item } = await docClient.send(new GetCommand({
            TableName: "TestifyUsers",
            Key: { email: departmentId }
        }));
        if (Item) {
            return res.status(400).json({ message: 'Department with this name already exists.' });
        }

        const newDepartment = {
            email: departmentId,
            departmentName: departmentName,
            recordType: "Department"
        };

        await docClient.send(new PutCommand({
            TableName: "TestifyUsers",
            Item: newDepartment
        }));
        res.status(201).json({ message: 'Department added successfully.' });
    } catch (error) {
        console.error("Add Department Error:", error);
        res.status(500).json({ message: 'Server error adding department.' });
    }
});

app.get('/api/departments', async (req, res) => {
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyUsers",
            FilterExpression: "recordType = :type",
            ExpressionAttributeValues: {
                ":type": "Department"
            }
        }));
        Items.sort((a, b) => a.departmentName.localeCompare(b.departmentName));
        res.json(Items);
    } catch (error) {
        console.error("Get Departments Error:", error);
        res.status(500).json({ message: 'Server error fetching departments.' });
    }
});

app.delete('/api/departments/:departmentName', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { departmentName } = req.params;
    try {
        const departmentId = `department#${departmentName}`;
        await docClient.send(new DeleteCommand({
            TableName: "TestifyUsers",
            Key: { email: departmentId }
        }));
        res.json({ message: 'Department deleted successfully.' });
    } catch (error) {
        console.error("Delete Department Error:", error);
        res.status(500).json({ message: 'Server error deleting department.' });
    }
});


// =================================================================
// --- STUDENT PROFILE ROUTES ---
// =================================================================

// Get student profile
app.get('/api/student/profile', authMiddleware, async (req, res) => {
    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: "TestifyUsers",
            Key: { email: req.user.email }
        }));
        if (Item) {
            delete Item.password;
            res.json(Item);
        } else {
            res.status(404).json({ message: 'User not found.' });
        }
    } catch (error) {
        console.error("Get Profile Error:", error);
        res.status(500).json({ message: 'Server error fetching profile.' });
    }
});

// Update student profile
app.put('/api/student/profile', authMiddleware, async (req, res) => {
    const { mobile, department, rollNumber } = req.body;
    try {
        await docClient.send(new UpdateCommand({
            TableName: "TestifyUsers",
            Key: { email: req.user.email },
            UpdateExpression: "set mobile = :m, department = :d, rollNumber = :rn",
            ExpressionAttributeValues: {
                ":m": mobile,
                ":d": department,
                ":rn": rollNumber
            }
        }));
        res.json({ message: 'Profile updated successfully.' });
    } catch (error) {
        console.error("Update Profile Error:", error);
        res.status(500).json({ message: 'Server error updating profile.' });
    }
});

// Upload profile image (STUDENT - ONE TIME ONLY)
app.post('/api/student/profile/image', authMiddleware, upload.single('profileImage'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No image file uploaded.' });
    }
    try {
        const { Item: user } = await docClient.send(new GetCommand({
            TableName: "TestifyUsers",
            Key: { email: req.user.email }
        }));

        if (user && user.profileImageUrl) {
            return res.status(403).json({ message: 'Profile image can only be uploaded once. Please contact an administrator to change it.' });
        }

        const b64 = Buffer.from(req.file.buffer).toString("base64");
        let dataURI = "data:" + req.file.mimetype + ";base64," + b64;
        const result = await cloudinary.uploader.upload(dataURI, {
            folder: "profile_pictures"
        });

        await docClient.send(new UpdateCommand({
            TableName: "TestifyUsers",
            Key: { email: req.user.email },
            UpdateExpression: "set profileImageUrl = :url",
            ExpressionAttributeValues: {
                ":url": result.secure_url
            }
        }));

        res.json({ message: 'Image uploaded successfully.', imageUrl: result.secure_url });
    } catch (error) {
        console.error("Image Upload Error:", error);
        res.status(500).json({ message: 'Server error uploading image.' });
    }
});

// =================================================================
// --- AI TEST GENERATION ROUTE ---
// =================================================================
app.post('/api/admin/generate-test-from-pdf', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }

    const { text } = req.body;
    if (!text) {
        return res.status(400).json({ message: 'No text provided from PDF.' });
    }

    try {
        const prompt = `Based on the following text which contains questions and answers, create a complete, structured JSON object for a test. The JSON must have a 'testTitle' (string), 'duration' (number, in minutes), 'totalMarks' (number), 'passingPercentage' (number), and an array of 'questions'. Each question object in the array must have:
- 'text' (string): The question text.
- 'type' (string): Can be 'mcq-single', 'mcq-multiple', or 'fill-blank'.
- 'marks' (number): The marks for the question.
- 'options' (array of strings): For 'mcq-single' and 'mcq-multiple' types.
- 'correctAnswer' (string): For 'mcq-single' (the index of the correct option, e.g., "0") and 'fill-blank' (the exact answer string).
- 'correctAnswers' (array of strings): For 'mcq-multiple' (an array of the indices of correct options, e.g., ["0", "2"]).
Here is the text:\n\n${text}`;

        const schema = {
            type: "OBJECT",
            properties: {
                "testTitle": { "type": "STRING" },
                "duration": { "type": "NUMBER" },
                "totalMarks": { "type": "NUMBER" },
                "passingPercentage": { "type": "NUMBER" },
                "questions": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "text": { "type": "STRING" },
                            "type": { "type": "STRING", "enum": ["mcq-single", "mcq-multiple", "fill-blank"] },
                            "marks": { "type": "NUMBER" },
                            "options": { "type": "ARRAY", "items": { "type": "STRING" } },
                            "correctAnswer": { "type": "STRING" },
                            "correctAnswers": { "type": "ARRAY", "items": { "type": "STRING" } }
                        },
                        "required": ["text", "type", "marks"]
                    }
                }
            },
            required: ["testTitle", "duration", "totalMarks", "passingPercentage", "questions"]
        };

        const apiKey = 'AIzaSyAR_X4MZ75vxwV7OTU3dabFRcVe4SxWpb8';

        if (!apiKey) {
            throw new Error("GEMINI_API_KEY is not configured on the server.");
        }
        const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key=${apiKey}`;

        const payload = {
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: {
                responseMimeType: "application/json",
                responseSchema: schema
            }
        };

        const apiResponse = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!apiResponse.ok) {
            const errorBody = await apiResponse.text();
            console.error("Gemini API Error:", errorBody);
            throw new Error(`AI API call failed with status: ${apiResponse.status}`);
        }

        const result = await apiResponse.json();
        const jsonText = result.candidates[0].content.parts[0].text;
        const structuredTest = JSON.parse(jsonText);

        res.json(structuredTest);

    } catch (error) {
        console.error('Error in AI test generation backend:', error);
        res.status(500).json({ message: 'Failed to generate test from AI.' });
    }
});


// --- HELPER FUNCTION FOR AUTOMATIC CERTIFICATE ISSUANCE ---
async function issueCertificateAutomatically(testId, studentEmail) {
    try {
        const existingCerts = await docClient.send(new ScanCommand({
            TableName: "TestifyCertificates",
            FilterExpression: "testId = :tid AND studentEmail = :email",
            ExpressionAttributeValues: { ":tid": testId, ":email": studentEmail }
        }));

        if (existingCerts.Items && existingCerts.Items.length > 0) {
            console.log(`Certificate already exists for ${studentEmail} for test ${testId}. Skipping.`);
            return;
        }

        const { Item: student } = await docClient.send(new GetCommand({
            TableName: "TestifyUsers",
            Key: { email: studentEmail }
        }));

        const { Item: test } = await docClient.send(new GetCommand({
            TableName: "TestifyTests",
            Key: { testId }
        }));

        if (!student || !test) {
            console.error(`Could not find student or test for auto-issuing certificate. Student: ${studentEmail}, Test: ${testId}`);
            return;
        }

        const studentName = student.fullName;
        const testTitle = test.title;
        const issueDate = new Date().toLocaleDateString();
        const certificateId = uuidv4();

        await docClient.send(new PutCommand({
            TableName: "TestifyCertificates",
            Item: {
                certificateId,
                studentEmail,
                testId,
                testTitle,
                issuedAt: new Date().toISOString()
            }
        }));

       const mailOptions = {
    from: '"TESTIFY" <testifylearning.help@gmail.com>',
    to: result.studentEmail,
    subject: `Congratulations! You've earned a certificate for ${testTitle}`,
    html: `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>Certificate of Achievement</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap');
        body { font-family: 'Poppins', Arial, sans-serif; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }
        a { text-decoration: none; }
        @media screen and (max-width: 600px) {
            .content-width {
                width: 90% !important;
            }
        }
    </style>
</head>
<body style="background-color: #f3f4f6; margin: 0; padding: 0;">
    <!-- Preheader text for inbox preview -->
    <span style="display:none;font-size:1px;color:#ffffff;line-height:1px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;">
        Congratulations on earning your certificate!
    </span>
    <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #f3f4f6;">
        <tr>
            <td align="center" style="padding: 40px 20px;">
                <!-- Main Card -->
                <table class="content-width" width="600" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #ffffff; border-radius: 12px; box-shadow: 0 10px 30px -10px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td align="center" style="padding: 30px 40px 20px; border-bottom: 1px solid #e5e7eb;">
                            <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1756037774/Gemini_Generated_Image_eu0ib0eu0ib0eu0i_z0amjh.png" 
                                 alt="Testify Logo" style="height: 50px; width: auto;">
                        </td>
                    </tr>
                    
                    <!-- Content Body -->
                    <tr>
                        <td align="center" style="padding: 40px; text-align: center;">
                             <h1 style="font-family: 'Poppins', Arial, sans-serif; font-size: 26px; font-weight: 700; color: #111827; margin: 0 0 15px;">Certificate Earned!</h1>
                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 16px; color: #4b5563; margin: 0 0 30px; line-height: 1.7;">
                                 Congratulations, <b>${studentName}</b>! You've successfully passed the test for "<b>${testTitle}</b>". Your new certificate is waiting for you in your dashboard.
                             </p>
                             <a href="https://testify-io-ai.onrender.com/student/my-certificates.html" 
                                target="_blank"
                                style="display: inline-block; padding: 15px 35px; font-family: 'Poppins', Arial, sans-serif; font-size: 16px; font-weight: 600; color: #ffffff; background-color: #4338ca; border-radius: 8px; text-decoration: none;">
                                 View My Certificate
                             </a>
                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 14px; color: #6b7280; margin: 30px 0 0;">
                                 Well done on your achievement!
                             </p>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td align="center" style="padding: 30px 40px; background-color: #f9fafb; border-top: 1px solid #e5e7eb; border-radius: 0 0 12px 12px;">
                            <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0 0 8px;">
                                &copy; ${new Date().getFullYear()} TESTIFY. All rights reserved.
                            </p>
                            <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0;">
                                Houston, TX, USA | <a href="mailto:testifylearning.help@gmail.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>`
};



       await sendEmailWithResend(mailOptions);
        console.log(`Successfully auto-issued certificate to ${studentEmail} for test ${testTitle}`);

    } catch (error) {
        console.error(`Error auto-issuing certificate for ${studentEmail}:`, error);
    }
}

// =================================================================
// --- ROOT ROUTE ---
// =================================================================

app.get('/', (req, res) => {
    res.redirect('/welcome.html');
});


// =================================================================
// --- AUTHENTICATION ROUTES ---
// =================================================================

app.post('/api/signup', async (req, res) => {
    // This endpoint now expects all the fields from the new signup form
    const { fullName, email, mobile, college, department, year, rollNumber, password } = req.body;
    
    // Validate that all required fields are present
    if (!fullName || !email || !mobile || !college || !department || !year || !rollNumber || !password) {
        return res.status(400).json({ message: 'Please fill all fields.' });
    }

    try {
        // Check if a user with the same email already exists
        const existingUser = await docClient.send(new GetCommand({ 
            TableName: "TestifyUsers", 
            Key: { email: email.toLowerCase() } 
        }));
        if (existingUser.Item) {
            return res.status(400).json({ message: 'User with this email already exists.' });
        }

        // Hash the password for security
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create the new user object
        const newUser = {
            email: email.toLowerCase(),
            fullName,
            mobile,
            college,
            year,
            department,
            rollNumber,
            password: hashedPassword,
            role: "Student", // Default role for signup
            isBlocked: false
        };

        // Save the new user to the database
        await docClient.send(new PutCommand({ TableName: "TestifyUsers", Item: newUser }));
        
        res.status(201).json({ message: 'Account created successfully! Please log in.' });

    } catch (error) {
        console.error("Signup Error:", error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Please provide email and password.' });
    try {
        const { Item } = await docClient.send(new GetCommand({ TableName: "TestifyUsers", Key: { email: email.toLowerCase() } }));
        if (!Item) return res.status(400).json({ message: 'Invalid credentials.' });

        if (Item.isBlocked) {
            return res.status(403).json({ message: 'Your account has been blocked by the administrator.' });
        }

        const isMatch = await bcrypt.compare(password, Item.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials.' });
        
        const payload = { 
            user: { 
                email: Item.email, 
                fullName: Item.fullName, 
                role: Item.role, 
                college: Item.college,
                assignedColleges: Item.assignedColleges,
                profileImageUrl: Item.profileImageUrl || null 
            } 
        };

        jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' }, (err, token) => {
            if (err) throw err;
            res.json({ message: 'Login successful!', token, user: payload.user });
        });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});


// =================================================================
// --- ADMIN & MODERATOR SHARED ROUTES (TESTS) ---
// =================================================================

const adminOrModeratorAuth = (req, res, next) => {
    if (req.user.role !== 'Admin' && req.user.role !== 'Moderator') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    next();
};

app.post('/api/tests', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    
    const { testTitle, duration, totalMarks, passingPercentage, questions } = req.body;
    const testId = uuidv4();

    const newTest = {
        testId,
        title: testTitle,
        duration,
        totalMarks,
        passingPercentage,
        questions,
        createdAt: new Date().toISOString(),
        status: 'Not Assigned',
        resultsPublished: false,
        autoIssueCertificates: false 
    };

    try {
        await docClient.send(new PutCommand({ TableName: "TestifyTests", Item: newTest }));
        res.status(201).json({ message: 'Test created successfully!', test: newTest });
    } catch (error) {
        console.error("Create Test Error:", error);
        res.status(500).json({ message: 'Server error creating test.' });
    }
});

app.get('/api/tests', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    try {
        const { Items } = await docClient.send(new ScanCommand({ TableName: "TestifyTests" }));
        res.json(Items);
    } catch (error) {
        console.error("Get Tests Error:", error);
        res.status(500).json({ message: 'Server error fetching tests.' });
    }
});

app.post('/api/assign-test', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    const { testId, testName, colleges, studentEmails, sendEmail, autoIssueCertificates } = req.body;

    try {
        let studentsToNotify = [];

        // --- FIX APPLIED HERE ---
        // Logic for assigning to specific students, which now allows for retakes.
        if (studentEmails && studentEmails.length > 0) {
            for (const email of studentEmails) {
                // 1. Find and delete any existing result for this student and test. This is the key to allowing a retake.
                const { Items: existingResults } = await docClient.send(new ScanCommand({
                    TableName: "TestifyResults",
                    FilterExpression: "studentEmail = :email AND testId = :tid",
                    ExpressionAttributeValues: { ":email": email, ":tid": testId }
                }));

                if (existingResults && existingResults.length > 0) {
                    const deleteRequests = existingResults.map(result => ({
                        DeleteRequest: { Key: { resultId: result.resultId } }
                    }));
                    
                    // Batch delete for efficiency
                    const batches = [];
                    for (let i = 0; i < deleteRequests.length; i += 25) {
                        batches.push(deleteRequests.slice(i, i + 25));
                    }
                    for (const batch of batches) {
                        await docClient.send(new BatchWriteCommand({
                            RequestItems: { "TestifyResults": batch }
                        }));
                    }
                }

                // 2. Ensure an assignment record exists. If the student was never assigned, create one.
                const { Items: existingAssignments } = await docClient.send(new ScanCommand({
                    TableName: "TestifyAssignments",
                    FilterExpression: "studentEmail = :email AND testId = :tid",
                    ExpressionAttributeValues: { ":email": email, ":tid": testId }
                }));
                
                if (!existingAssignments || existingAssignments.length === 0) {
                    const assignmentId = uuidv4();
                    await docClient.send(new PutCommand({
                        TableName: "TestifyAssignments",
                        Item: { assignmentId, testId, studentEmail: email, assignedAt: new Date().toISOString() }
                    }));
                }
            }
            studentsToNotify = studentEmails;
        } 
        // --- SECONDARY FIX APPLIED HERE ---
        // Logic for assigning to entire colleges. This now correctly creates assignment records.
        else if (colleges && colleges.length > 0) {
            if (req.user.role === 'Moderator') {
                const isAllowed = colleges.every(college => req.user.assignedColleges.includes(college));
                if (!isAllowed) {
                    return res.status(403).json({ message: 'You can only assign tests to your assigned colleges.' });
                }
            }
            
            const filterExpression = colleges.map((_, index) => `college = :c${index}`).join(' OR ');
            const expressionAttributeValues = {};
            colleges.forEach((college, index) => {
                expressionAttributeValues[`:c${index}`] = college;
            });
            const { Items: studentsInColleges } = await docClient.send(new ScanCommand({
                TableName: "TestifyUsers",
                FilterExpression: filterExpression,
                ExpressionAttributeValues: expressionAttributeValues
            }));

            if (studentsInColleges.length > 0) {
                const assignmentWrites = studentsInColleges.map(student => ({
                    PutRequest: {
                        Item: {
                            assignmentId: uuidv4(),
                            testId: testId,
                            studentEmail: student.email,
                            assignedAt: new Date().toISOString()
                        }
                    }
                }));

                const batches = [];
                for (let i = 0; i < assignmentWrites.length; i += 25) {
                    batches.push(assignmentWrites.slice(i, i + 25));
                }
                for (const batch of batches) {
                    await docClient.send(new BatchWriteCommand({
                        RequestItems: { "TestifyAssignments": batch }
                    }));
                }
            }
            studentsToNotify = studentsInColleges.map(s => s.email);
        }

        // Update the overall status of the test
        if (req.user.role === 'Admin') {
            await docClient.send(new UpdateCommand({
                TableName: "TestifyTests",
                Key: { testId },
                UpdateExpression: "set #status = :status, #autoIssue = :autoIssue",
                ExpressionAttributeNames: { "#status": "status", "#autoIssue": "autoIssueCertificates" },
                ExpressionAttributeValues: { ":status": `Assigned`, ":autoIssue": autoIssueCertificates }
            }));
        }

        // Send email notifications
        if (sendEmail && studentsToNotify.length > 0) {
    const mailOptions = {
        from: '"TESTIFY" <testifylearning.help@gmail.com>',
        to: studentsToNotify.join(','),
        subject: `New Test Assigned: ${testName}`,
        html: `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>New Test Assigned</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap');
        body { font-family: 'Poppins', Arial, sans-serif; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }
        a { text-decoration: none; }
        @media screen and (max-width: 600px) {
            .content-width {
                width: 90% !important;
            }
        }
    </style>
</head>
<body style="background-color: #f3f4f6; margin: 0; padding: 0;">
    <!-- Preheader text for inbox preview -->
    <span style="display:none;font-size:1px;color:#ffffff;line-height:1px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;">
        You have a new test waiting for you.
    </span>
    <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #f3f4f6;">
        <tr>
            <td align="center" style="padding: 40px 20px;">
                <!-- Main Card -->
                <table class="content-width" width="600" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #ffffff; border-radius: 12px; box-shadow: 0 10px 30px -10px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td align="center" style="padding: 30px 40px 20px; border-bottom: 1px solid #e5e7eb;">
                            <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1756037774/Gemini_Generated_Image_eu0ib0eu0ib0eu0i_z0amjh.png" 
                                 alt="Testify Logo" style="height: 50px; width: auto;">
                        </td>
                    </tr>
                    
                    <!-- Content Body -->
                    <tr>
                        <td align="center" style="padding: 40px; text-align: center;">
                             <h1 style="font-family: 'Poppins', Arial, sans-serif; font-size: 26px; font-weight: 700; color: #111827; margin: 0 0 15px;">New Test Assigned</h1>
                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 16px; color: #4b5563; margin: 0 0 30px; line-height: 1.7;">
                                 A new test, "<b>${testName}</b>", has been assigned to you. Please log in to your TESTIFY dashboard to take the test.
                             </p>
                             <a href="https://testify-io-ai.onrender.com/student/take-test.html" 
                                target="_blank"
                                style="display: inline-block; padding: 15px 35px; font-family: 'Poppins', Arial, sans-serif; font-size: 16px; font-weight: 600; color: #ffffff; background-color: #3b82f6; border-radius: 8px; text-decoration: none;">
                                 Go to Test
                             </a>
                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 14px; color: #6b7280; margin: 30px 0 0;">
                                 Good luck!
                             </p>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td align="center" style="padding: 30px 40px; background-color: #f9fafb; border-top: 1px solid #e5e7eb; border-radius: 0 0 12px 12px;">
                            <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0 0 8px;">
                                &copy; ${new Date().getFullYear()} TESTIFY. All rights reserved.
                            </p>
                            <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0;">
                                Houston, TX, USA | <a href="mailto:testifylearning.help@gmail.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>`
    };
    // Your email sending logic would go here

           await sendEmailWithResend(mailOptions);
        }
        res.status(200).json({ message: 'Test assigned successfully!' });
    } catch (error) {
        console.error("Assign Test Error:", error);
        res.status(500).json({ message: 'Server error assigning test.' });
    }
});
// =================================================================
// --- PUBLISH RESULTS ROUTE (ADMIN) ---
// =================================================================
app.post('/api/publish-results', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { testId } = req.body;
    if (!testId) {
        return res.status(400).json({ message: 'Test ID is required.' });
    }
    try {
        await docClient.send(new UpdateCommand({
            TableName: "TestifyTests",
            Key: { testId },
            UpdateExpression: "set resultsPublished = :true",
            ExpressionAttributeValues: { ":true": true }
        }));
        res.status(200).json({ message: 'Results published successfully.' });
    } catch (error) {
        console.error("Publish Results Error:", error);
        res.status(500).json({ message: 'Server error publishing results.' });
    }
});


app.get('/api/admin/test-history', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    try {
        const { Items: tests } = await docClient.send(new ScanCommand({ TableName: "TestifyTests" }));
        let { Items: results } = await docClient.send(new ScanCommand({ TableName: "TestifyResults" }));

        if (req.user.role === 'Moderator') {
            const { Items: studentsInColleges } = await docClient.send(new ScanCommand({
                TableName: "TestifyUsers",
                FilterExpression: req.user.assignedColleges.map((_, i) => `college = :c${i}`).join(' OR '),
                ExpressionAttributeValues: req.user.assignedColleges.reduce((acc, val, i) => ({ ...acc, [`:c${i}`]: val }), {})
            }));
            const studentEmails = new Set(studentsInColleges.map(s => s.email));
            results = results.filter(r => studentEmails.has(r.studentEmail));
        }

        const history = tests.map(test => {
            const relevantResults = results.filter(r => r.testId === test.testId);
            const passedCount = relevantResults.filter(r => r.result === 'Pass').length;
            const failedCount = relevantResults.length - passedCount;
            
            return {
                testId: test.testId,
                title: test.title,
                attempted: relevantResults.length,
                passed: passedCount,
                failed: failedCount,
                resultsPublished: test.resultsPublished || false
            };
        });

        res.json(history);
    } catch (error) {
        console.error("Get Test History Error:", error);
        res.status(500).json({ message: 'Server error fetching history.' });
    }
});

app.get('/api/admin/dashboard-data', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });

    try {
        const { Items: tests } = await docClient.send(new ScanCommand({ TableName: "TestifyTests" }));
        const { Items: students } = await docClient.send(new ScanCommand({ TableName: "TestifyUsers", FilterExpression: "#role = :student", ExpressionAttributeNames: {"#role": "role"}, ExpressionAttributeValues: {":student": "Student"} }));
        const { Items: results } = await docClient.send(new ScanCommand({ TableName: "TestifyResults" }));

        const totalTests = tests.length;
        const totalStudents = students.length;
        const totalAttempts = results.length;
        const passedCount = results.filter(r => r.result === 'Pass').length;
        const avgPassRate = totalAttempts > 0 ? Math.round((passedCount / totalAttempts) * 100) : 0;

        const collegeCounts = students.reduce((acc, student) => {
            acc[student.college] = (acc[student.college] || 0) + 1;
            return acc;
        }, {});
        const collegeData = {
            labels: Object.keys(collegeCounts),
            counts: Object.values(collegeCounts)
        };

        const testPerformance = tests.map(test => {
            const relevantResults = results.filter(r => r.testId === test.testId);
            const totalScore = relevantResults.reduce((sum, r) => sum + r.score, 0);
            return {
                title: test.title,
                avgScore: relevantResults.length > 0 ? Math.round(totalScore / relevantResults.length) : 0
            };
        });
        const performanceData = {
            labels: testPerformance.map(t => t.title),
            scores: testPerformance.map(t => t.avgScore)
        };
        
        const studentMap = new Map(students.map(s => [s.email, s.fullName]));
        const testMap = new Map(tests.map(t => [t.testId, t.title]));
        const recentSubmissions = results
            .sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt))
            .slice(0, 5)
            .map(r => ({
                ...r,
                studentName: studentMap.get(r.studentEmail) || 'Unknown',
                testTitle: testMap.get(r.testId) || 'Unknown'
            }));

        res.json({
            stats: { totalTests, totalStudents, totalAttempts, avgPassRate },
            collegeData,
            performanceData,
            recentSubmissions
        });

    } catch (error) {
        console.error("Get Admin Dashboard Error:", error);
        res.status(500).json({ message: 'Server error fetching dashboard data.' });
    }
});

// =================================================================
// --- COURSE MANAGEMENT ROUTES (ADMIN & MODERATOR) ---
// =================================================================
app.post('/api/admin/courses', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    const { title, description, modules, mainTestId } = req.body;
    const courseId = uuidv4();
    const processedModules = modules.map(module => ({
        title: module.title,
        moduleId: uuidv4(),
        subModules: module.subModules.map(subModule => ({
            title: subModule.title,
            textContent: subModule.textContent || '',
            videoUrl: subModule.videoUrl || '',
            imageUrl: subModule.imageUrl || '',
            subModuleId: uuidv4()
        }))
    }));
    const newCourse = {
        courseId, title, description, modules: processedModules, mainTestId,
        createdAt: new Date().toISOString()
    };
    try {
        await docClient.send(new PutCommand({ TableName: "TestifyCourses", Item: newCourse }));
        res.status(201).json({ message: 'Course created successfully!', course: newCourse });
    } catch (error) {
        console.error("Create Course Error:", error);
        res.status(500).json({ message: 'Server error creating course.' });
    }
});

app.get('/api/admin/courses', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    try {
        const { Items } = await docClient.send(new ScanCommand({ TableName: "TestifyCourses" }));
        res.json(Items);
    } catch (error) {
        console.error("Get Courses Error:", error);
        res.status(500).json({ message: 'Server error fetching courses.' });
    }
});

app.get('/api/admin/courses/:id', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: "TestifyCourses",
            Key: { courseId: req.params.id }
        }));
        if (Item) {
            res.json(Item);
        } else {
            res.status(404).json({ message: 'Course not found' });
        }
    } catch (error) {
        console.error("Get Single Course Error:", error);
        res.status(500).json({ message: 'Server error fetching course.' });
    }
});

app.put('/api/admin/courses/:id', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    
    const { title, description, modules, mainTestId } = req.body;
    const courseId = req.params.id;

    const processedModules = modules.map(module => ({
        ...module,
        moduleId: module.moduleId || uuidv4(),
        subModules: module.subModules.map(subModule => ({
            ...subModule,
            subModuleId: subModule.subModuleId || uuidv4()
        }))
    }));

    try {
        const { Item: existingCourse } = await docClient.send(new GetCommand({ TableName: "TestifyCourses", Key: { courseId } }));
        if (!existingCourse) {
            return res.status(404).json({ message: 'Course not found for update.' });
        }

        const updatedCourse = {
            courseId,
            title,
            description,
            modules: processedModules,
            mainTestId,
            createdAt: existingCourse.createdAt
        };

        await docClient.send(new PutCommand({
            TableName: "TestifyCourses",
            Item: updatedCourse
        }));
        res.status(200).json({ message: 'Course updated successfully!', course: updatedCourse });
    } catch (error) {
        console.error("Update Course Error:", error);
        res.status(500).json({ message: 'Server error updating course.' });
    }
});

app.post('/api/admin/assign-course', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    const { courseId, colleges, studentEmails, sendEmail } = req.body;
    let studentsToAssign = [];

    try {
        const { Item: course } = await docClient.send(new GetCommand({ TableName: "TestifyCourses", Key: { courseId } }));
        if (!course) {
            return res.status(404).json({ message: "Course not found." });
        }

        if (studentEmails && studentEmails.length > 0) {
            const keys = studentEmails.map(email => ({ email }));
            const { Responses } = await docClient.send(new BatchGetCommand({
                RequestItems: { "TestifyUsers": { Keys: keys } }
            }));
            studentsToAssign = Responses.TestifyUsers || [];
        } 
        else if (colleges && colleges.length > 0) {
            if (req.user.role === 'Moderator') {
                const isAllowed = colleges.every(college => req.user.assignedColleges.includes(college));
                if (!isAllowed) {
                    return res.status(403).json({ message: 'You can only assign courses to your assigned colleges.' });
                }
            }
            const filterExpression = colleges.map((_, index) => `college = :c${index}`).join(' OR ');
            const expressionAttributeValues = {};
            colleges.forEach((college, index) => {
                expressionAttributeValues[`:c${index}`] = college;
            });

            const { Items } = await docClient.send(new ScanCommand({
                TableName: "TestifyUsers",
                FilterExpression: filterExpression,
                ExpressionAttributeValues: expressionAttributeValues
            }));
            studentsToAssign = Items;
        }

        if (studentsToAssign.length === 0) {
            return res.status(400).json({ message: "No students found for assignment." });
        }

        for (const student of studentsToAssign) {
            const progressId = uuidv4();
            const progressRecord = {
                progressId,
                courseId,
                studentEmail: student.email,
                status: 'Not Started',
                completedSubModules: [],
                mainTestAssigned: false,
                assignedAt: new Date().toISOString()
            };
            await docClient.send(new PutCommand({ TableName: "TestifyCourseProgress", Item: progressRecord }));
        }

        if (sendEmail) {
    const studentEmails = studentsToAssign.map(s => s.email);
    const appBaseUrl = req.headers.origin || 'http://localhost:3000';
    const loginLink = `${appBaseUrl}/login`; // Or your specific dashboard URL

    const mailOptions = {
        from: '"TESTIFY" <testifylearning.help@gmail.com>',
        to: studentEmails.join(','),
        subject: `New Course Assigned: ${course.title}`,
        html: `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>New Course Assigned</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap');
        body { font-family: 'Poppins', Arial, sans-serif; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }
        a { text-decoration: none; }
        @media screen and (max-width: 600px) {
            .content-width {
                width: 90% !important;
            }
        }
    </style>
</head>
<body style="background-color: #f3f4f6; margin: 0; padding: 0;">
    <!-- Preheader text for inbox preview -->
    <span style="display:none;font-size:1px;color:#ffffff;line-height:1px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;">
        You've been enrolled in a new course!
    </span>
    <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #f3f4f6;">
        <tr>
            <td align="center" style="padding: 40px 20px;">
                <!-- Main Card -->
                <table class="content-width" width="600" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #ffffff; border-radius: 12px; box-shadow: 0 10px 30px -10px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td align="center" style="padding: 30px 40px 20px; border-bottom: 1px solid #e5e7eb;">
                            <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1756037774/Gemini_Generated_Image_eu0ib0eu0ib0eu0i_z0amjh.png" 
                                 alt="Testify Logo" style="height: 50px; width: auto;">
                        </td>
                    </tr>
                    
                    <!-- Content Body -->
                    <tr>
                        <td align="center" style="padding: 40px; text-align: center;">
                             <h1 style="font-family: 'Poppins', Arial, sans-serif; font-size: 26px; font-weight: 700; color: #111827; margin: 0 0 15px;">You're Enrolled!</h1>
                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 16px; color: #4b5563; margin: 0 0 30px; line-height: 1.7;">
                                 A new course, "<b>${course.title}</b>", has been assigned to you. Click the button below to log in and start learning.
                             </p>
                             <a href="https://testify-io-ai.onrender.com/student/my-courses.html" 
                                target="_blank"
                                style="display: inline-block; padding: 15px 35px; font-family: 'Poppins', Arial, sans-serif; font-size: 16px; font-weight: 600; color: #ffffff; background-color: #3b82f6; border-radius: 8px; text-decoration: none;">
                                 Go to Course
                             </a>
                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 14px; color: #6b7280; margin: 30px 0 0;">
                                 Happy learning!
                             </p>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td align="center" style="padding: 30px 40px; background-color: #f9fafb; border-top: 1px solid #e5e7eb; border-radius: 0 0 12px 12px;">
                            <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0 0 8px;">
                                &copy; ${new Date().getFullYear()} TESTIFY. All rights reserved.
                            </p>
                            <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0;">
                                Houston, TX, USA | <a href="mailto:testifylearning.help@gmail.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>`
    };
    // You would add your email sending logic here, e.g., transporter.sendMail(mailOptions);


           await sendEmailWithResend(mailOptions);
        }

        res.status(200).json({ message: `Course assigned to ${studentsToAssign.length} students successfully!` });
    } catch (error) {
        console.error("Assign Course Error:", error);
        res.status(500).json({ message: 'Server error assigning course.' });
    }
});

// =================================================================
// --- STUDENT ROUTES (COURSES) ---
// =================================================================
app.get('/api/student/my-courses', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });

    try {
        const { Items: progressRecords } = await docClient.send(new QueryCommand({
            TableName: "TestifyCourseProgress",
            IndexName: "StudentEmailIndex",
            KeyConditionExpression: "studentEmail = :email",
            ExpressionAttributeValues: { ":email": req.user.email }
        }));

        if (!progressRecords || progressRecords.length === 0) {
            return res.json([]);
        }

        const courseIds = [...new Set(progressRecords.map(p => p.courseId))];
        const keys = courseIds.map(courseId => ({ courseId }));
        
        const { Responses } = await docClient.send(new BatchGetCommand({
            RequestItems: { "TestifyCourses": { Keys: keys } }
        }));
        const courses = Responses.TestifyCourses || [];
        const courseMap = new Map(courses.map(c => [c.courseId, c]));

        const myCourses = progressRecords.map(progress => {
            const courseDetails = courseMap.get(progress.courseId);
            if (!courseDetails) return null;

            const totalSubModules = courseDetails.modules.reduce((acc, module) => acc + module.subModules.length, 0);
            const completedCount = progress.completedSubModules.length;
            const completionPercentage = totalSubModules > 0 ? Math.round((completedCount / totalSubModules) * 100) : 0;

            return {
                ...progress,
                title: courseDetails.title,
                description: courseDetails.description,
                completionPercentage
            };
        }).filter(Boolean);

        res.json(myCourses);
    } catch (error) {
        console.error("Get My Courses Error:", error);
        res.status(500).json({ message: 'Server error fetching courses.' });
    }
});

app.get('/api/student/courses/:id', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    
    const courseId = req.params.id;
    const studentEmail = req.user.email;

    try {
        const { Items } = await docClient.send(new QueryCommand({
            TableName: "TestifyCourseProgress",
            IndexName: "StudentEmailIndex",
            KeyConditionExpression: "studentEmail = :email",
            FilterExpression: "courseId = :cid",
            ExpressionAttributeValues: { ":email": studentEmail, ":cid": courseId }
        }));

        if (!Items || Items.length === 0) {
            return res.status(403).json({ message: "Access denied: You are not assigned to this course." });
        }
        const progress = Items[0];

        const { Item: course } = await docClient.send(new GetCommand({
            TableName: "TestifyCourses",
            Key: { courseId }
        }));

        if (!course) {
            return res.status(404).json({ message: "Course content not found." });
        }

        res.json({ course, progress });

    } catch (error) {
        console.error("Get Single Course Content Error:", error);
        res.status(500).json({ message: 'Server error fetching course content.' });
    }
});

app.post('/api/student/courses/progress', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    
    const { courseId, subModuleId } = req.body;
    const studentEmail = req.user.email;

    try {
        const { Items } = await docClient.send(new QueryCommand({
            TableName: "TestifyCourseProgress",
            IndexName: "StudentEmailIndex",
            KeyConditionExpression: "studentEmail = :email",
            FilterExpression: "courseId = :cid",
            ExpressionAttributeValues: { ":email": studentEmail, ":cid": courseId }
        }));

        if (!Items || Items.length === 0) {
            return res.status(404).json({ message: "Course assignment not found for this student." });
        }
        const progressRecord = Items[0];

        if (!progressRecord.completedSubModules.includes(subModuleId)) {
            await docClient.send(new UpdateCommand({
                TableName: "TestifyCourseProgress",
                Key: { progressId: progressRecord.progressId },
                UpdateExpression: "SET completedSubModules = list_append(completedSubModules, :newSubModule)",
                ExpressionAttributeValues: { ":newSubModule": [subModuleId] }
            }));
            progressRecord.completedSubModules.push(subModuleId);
        }

        const { Item: course } = await docClient.send(new GetCommand({ TableName: "TestifyCourses", Key: { courseId } }));
        const totalSubModules = course.modules.reduce((acc, module) => acc + module.subModules.length, 0);

        if (progressRecord.completedSubModules.length >= totalSubModules && !progressRecord.mainTestAssigned) {
            await docClient.send(new UpdateCommand({
                TableName: "TestifyCourseProgress",
                Key: { progressId: progressRecord.progressId },
                UpdateExpression: "SET mainTestAssigned = :true, #stat = :completed",
                ExpressionAttributeNames: { "#stat": "status" },
                ExpressionAttributeValues: { ":true": true, ":completed": "Completed" }
            }));

            const { Item: test } = await docClient.send(new GetCommand({ TableName: "TestifyTests", Key: { testId: course.mainTestId } }));
            if (test) {
                const assignmentId = uuidv4();
                await docClient.send(new PutCommand({
                    TableName: "TestifyAssignments",
                    Item: {
                        assignmentId,
                        testId: course.mainTestId,
                        studentEmail: studentEmail, 
                        assignedAt: new Date().toISOString()
                    }
                }));
                
                const mailOptions = {
    from: '"TESTIFY" <testifylearning.help@gmail.com>',
    to: studentEmail,
    subject: `Final Test Unlocked for ${course.title}`,
    html: `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>Final Test Unlocked</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap');
        body { font-family: 'Poppins', Arial, sans-serif; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }
        a { text-decoration: none; }
        @media screen and (max-width: 600px) {
            .content-width {
                width: 90% !important;
            }
        }
    </style>
</head>
<body style="background-color: #f3f4f6; margin: 0; padding: 0;">
    <!-- Preheader text for inbox preview -->
    <span style="display:none;font-size:1px;color:#ffffff;line-height:1px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;">
        Your final test for ${course.title} is now available!
    </span>
    <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #f3f4f6;">
        <tr>
            <td align="center" style="padding: 40px 20px;">
                <!-- Main Card -->
                <table class="content-width" width="600" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #ffffff; border-radius: 12px; box-shadow: 0 10px 30px -10px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td align="center" style="padding: 30px 40px 20px; border-bottom: 1px solid #e5e7eb;">
                            <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1756037774/Gemini_Generated_Image_eu0ib0eu0ib0eu0i_z0amjh.png" 
                                 alt="Testify Logo" style="height: 50px; width: auto;">
                        </td>
                    </tr>
                    
                    <!-- Content Body -->
                    <tr>
                        <td align="center" style="padding: 40px; text-align: center;">
                             <h1 style="font-family: 'Poppins', Arial, sans-serif; font-size: 26px; font-weight: 700; color: #111827; margin: 0 0 15px;">Congratulations!</h1>
                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 16px; color: #4b5563; margin: 0 0 30px; line-height: 1.7;">
                                 You have completed the course "<b>${course.title}</b>". The final test, "<b>${test.title}</b>", is now unlocked in your dashboard.
                             </p>
                             <a href="https://testify-io-ai.onrender.com/student/take-test.html" 
                                target="_blank"
                                style="display: inline-block; padding: 15px 35px; font-family: 'Poppins', Arial, sans-serif; font-size: 16px; font-weight: 600; color: #ffffff; background-color: #16a34a; border-radius: 8px; text-decoration: none;">
                                 Start Final Test
                             </a>
                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 14px; color: #6b7280; margin: 30px 0 0;">
                                 Best of luck!
                             </p>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td align="center" style="padding: 30px 40px; background-color: #f9fafb; border-top: 1px solid #e5e7eb; border-radius: 0 0 12px 12px;">
                            <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0 0 8px;">
                                &copy; ${new Date().getFullYear()} TESTIFY. All rights reserved.
                            </p>
                            <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0;">
                                Houston, TX, USA | <a href="mailto:testifylearning.help@gmail.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>`
};

               await sendEmailWithResend(mailOptions);
            }
            res.json({ message: 'Progress updated. Course complete and final test assigned!' });
        } else {
            res.json({ message: 'Progress updated successfully.' });
        }

    } catch (error) {
        console.error("Update Progress Error:", error);
        res.status(500).json({ message: 'Server error updating progress.' });
    }
});


// =================================================================
// --- STUDENT ROUTES (TESTS) ---
// =================================================================
app.get('/api/student/dashboard-data', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });

    try {
        const studentEmail = req.user.email;
        const studentCollege = req.user.college;

        // --- Fetch Test Data ---
        const historyResponse = await docClient.send(new QueryCommand({
            TableName: "TestifyResults",
            IndexName: "StudentEmailIndex",
            KeyConditionExpression: "studentEmail = :email",
            ExpressionAttributeValues: { ":email": studentEmail }
        }));
        const allHistory = historyResponse.Items || [];

        const allTestIds = [...new Set(allHistory.map(r => r.testId))];
        let allTestsMap = new Map();
        if (allTestIds.length > 0) {
            const keys = allTestIds.map(testId => ({ testId }));
            const testsResponse = await docClient.send(new BatchGetCommand({
                RequestItems: { "TestifyTests": { Keys: keys } }
            }));
            const tests = testsResponse.Responses.TestifyTests || [];
            allTestsMap = new Map(tests.map(t => [t.testId, t]));
        }

        const history = allHistory.filter(r => {
            const testDetails = allTestsMap.get(r.testId);
            return testDetails && testDetails.resultsPublished === true;
        });

        let availableTests = [];
        if (studentCollege) {
            // This logic can be simplified in a real-world app with better indexing
            const assignmentsResponse = await docClient.send(new ScanCommand({
                TableName: "TestifyAssignments",
                FilterExpression: "studentEmail = :email",
                ExpressionAttributeValues: { ":email": studentEmail }
            }));
            const assignedTestIds = assignmentsResponse.Items.map(a => a.testId);

            if (assignedTestIds.length > 0) {
                const completedTestIds = allHistory.map(r => r.testId); 
                const availableTestIds = assignedTestIds.filter(id => !completedTestIds.includes(id));
                if (availableTestIds.length > 0) {
                    const keys = [...new Set(availableTestIds)].map(testId => ({ testId }));
                    const testsResponse = await docClient.send(new BatchGetCommand({
                        RequestItems: { "TestifyTests": { Keys: keys } }
                    }));
                    availableTests = testsResponse.Responses.TestifyTests || [];
                }
            }
        }

        const testsCompleted = history.length;
        const totalScore = history.reduce((sum, item) => sum + item.score, 0);
        const overallScore = testsCompleted > 0 ? Math.round(totalScore / testsCompleted) : 0;
        const passedCount = history.filter(item => item.result === 'Pass').length;
        const passRate = testsCompleted > 0 ? Math.round((passedCount / testsCompleted) * 100) : 0;
        
        const recentHistory = history
            .sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt))
            .slice(0, 3)
            .map(item => ({ ...item, testTitle: allTestsMap.get(item.testId)?.title || 'Unknown Test' }));

        // --- CORRECTED: Fetch Compiler/CodeLab Stats from the correct table ---
        // Scores are being saved to "TestifyCompilerScores", so we must read from there.
        const compilerScoresResponse = await docClient.send(new ScanCommand({
            TableName: "TestifyCompilerScores", // Corrected table name
            FilterExpression: "studentEmail = :email", // Simplified filter as this table only holds scores
            ExpressionAttributeValues: {
                ":email": studentEmail
            }
        }));
        const compilerScores = compilerScoresResponse.Items || [];

        const problemsSolved = compilerScores.length;
        const totalCodingScore = compilerScores.reduce((sum, item) => sum + (item.score || 0), 0);

        const recentCodingHistory = compilerScores
            .sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt))
            .slice(0, 3);

        res.json({
            stats: { 
                overallScore, 
                testsCompleted, 
                passRate,
                problemsSolved,
                totalCodingScore
            },
            newTests: availableTests,
            recentHistory,
            recentCodingHistory
        });

    } catch (error) {
        console.error("Get Student Dashboard Error:", error);
        res.status(500).json({ message: 'Server error fetching dashboard data.' });
    }
});
app.get('/api/student/tests', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    
    try {
        const studentEmail = req.user.email;
        const assignmentsResponse = await docClient.send(new ScanCommand({
            TableName: "TestifyAssignments",
            FilterExpression: "studentEmail = :email",
            ExpressionAttributeValues: { ":email": studentEmail }
        }));
        
        const assignments = assignmentsResponse.Items;

        if (!assignments || assignments.length === 0) {
            return res.json([]);
        }

        const resultsResponse = await docClient.send(new QueryCommand({
            TableName: "TestifyResults",
            IndexName: "StudentEmailIndex",
            KeyConditionExpression: "studentEmail = :email",
            ExpressionAttributeValues: { ":email": studentEmail }
        }));
        
        const results = resultsResponse.Items;
        const completedTestIds = new Set(results.map(r => r.testId));

        const availableTestIds = assignments
            .map(assignment => assignment.testId)
            .filter(testId => !completedTestIds.has(testId));

        if (availableTestIds.length === 0) {
            return res.json([]);
        }

        const uniqueTestIds = [...new Set(availableTestIds)];
        const keys = uniqueTestIds.map(testId => ({ testId }));
        
        const testsResponse = await docClient.send(new BatchGetCommand({
            RequestItems: { "TestifyTests": { Keys: keys } }
        }));
        
        res.json(testsResponse.Responses.TestifyTests || []);

    } catch (error) {
        console.error("Get Student Tests Error:", error);
        res.status(500).json({ message: 'Server error fetching student tests.' });
    }
});

app.post('/api/student/submit-test', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    
    const { testId, answers, timeTaken, violationReason, testData } = req.body;
    const studentEmail = req.user.email;
    const resultId = uuidv4();

    try {
        let test;
        // Logic to handle the static test case
        if (testId === 'cognizant-cloud-fundamentals-static' && testData) {
            test = testData;
        } else {
            // This is the existing logic for dynamic tests from the database
            const { Item } = await docClient.send(new GetCommand({
                TableName: "TestifyTests",
                Key: { testId }
            }));
            test = Item;
        }

        if (!test) {
            return res.status(404).json({ message: "Test not found." });
        }

        let marksScored = 0;
        test.questions.forEach((question, index) => {
            const studentAnswer = answers[index];
            if (studentAnswer === null || studentAnswer === undefined) return;
            
            if (String(studentAnswer).trim() === String(question.correctAnswer).trim()) {
                marksScored += parseInt(question.marks, 10);
            }
        });

        const percentageScore = Math.round((marksScored / test.totalMarks) * 100);
        const result = percentageScore >= test.passingPercentage ? "Pass" : "Fail";

        const newResult = {
            resultId,
            testId,
            studentEmail,
            studentName: req.user.fullName, 
            college: req.user.college, 
            testTitle: test.title, 
            answers,
            timeTaken,
            score: percentageScore,
            result,
            submittedAt: new Date().toISOString(),
            violationReason: violationReason || null 
        };
    
        await docClient.send(new PutCommand({ TableName: "TestifyResults", Item: newResult }));

        if (result === "Pass" && test.autoIssueCertificates === true && !violationReason) {
             issueCertificateAutomatically(testId, studentEmail);
        }

        res.status(201).json({ message: 'Test submitted successfully!' });

    } catch (error) {
        console.error("Submit Test Error:", error);
        res.status(500).json({ message: 'Server error submitting test.' });
    }
});
app.get('/api/student/history', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    try {
        const { Items: results } = await docClient.send(new QueryCommand({
            TableName: "TestifyResults",
            IndexName: "StudentEmailIndex",
            KeyConditionExpression: "studentEmail = :email",
            ExpressionAttributeValues: { ":email": req.user.email }
        }));

        if (!results || results.length === 0) {
            return res.json([]);
        }

        const dynamicTestIds = results.map(r => r.testId).filter(id => id !== 'cognizant-cloud-fundamentals-static');
        const testMap = new Map();

        if (dynamicTestIds.length > 0) {
            const keys = [...new Set(dynamicTestIds)].map(testId => ({ testId }));
            const { Responses } = await docClient.send(new BatchGetCommand({
                RequestItems: { 
                    "TestifyTests": { 
                        Keys: keys,
                        ProjectionExpression: "testId, title, #dur, resultsPublished",
                        ExpressionAttributeNames: { "#dur": "duration" }
                    } 
                }
            }));
            const tests = Responses.TestifyTests || [];
            tests.forEach(t => testMap.set(t.testId, t));
        }

        const enrichedHistory = results.map(result => {
            if (result.testId === 'cognizant-cloud-fundamentals-static') {
                // Handle the static test case directly
                return {
                    ...result,
                    testTitle: "Cognizant Cloud Fundamentals Quiz",
                    testDuration: 25, // Static value
                    resultsPublished: true // Always show results for this public test
                };
            }
            
            const testDetails = testMap.get(result.testId);
            if (testDetails && testDetails.resultsPublished === true) {
                return {
                    ...result,
                    testTitle: testDetails.title,
                    testDuration: testDetails.duration
                };
            }
            return null; 
        }).filter(Boolean); 
        
        res.json(enrichedHistory);
    } catch (error) {
        console.error("Get Student History Error:", error);
        res.status(500).json({ message: 'Server error fetching history.' });
    }
});

app.get('/api/tests/:id', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: "TestifyTests",
            Key: { testId: req.params.id }
        }));
        if (Item) {
            res.json(Item);
        } else {
            res.status(404).json({ message: 'Test not found' });
        }
    } catch (error) {
        console.error("Get Single Test Error:", error);
        res.status(500).json({ message: 'Server error fetching test.' });
    }
});

app.put('/api/tests/:id', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    
    const { testTitle, duration, totalMarks, passingPercentage, questions } = req.body;
    const testId = req.params.id;

    try {
        const { Item: existingTest } = await docClient.send(new GetCommand({
            TableName: "TestifyTests",
            Key: { testId }
        }));
        if (!existingTest) {
            return res.status(404).json({ message: 'Test not found for update.' });
        }

        const updatedTest = {
            ...existingTest, 
            title: testTitle,
            duration,
            passingPercentage,
            questions
        };

        await docClient.send(new PutCommand({
            TableName: "TestifyTests",
            Item: updatedTest
        }));
        res.status(200).json({ message: 'Test updated successfully!', test: updatedTest });
    } catch (error) {
        console.error("Update Test Error:", error);
        res.status(500).json({ message: 'Server error updating test.' });
    }
});

app.get('/api/admin/test-report/:testId', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    const { testId } = req.params;

    try {
        const { Item: test } = await docClient.send(new GetCommand({
            TableName: "TestifyTests",
            Key: { testId }
        }));

        if (!test) {
            return res.status(404).json({ message: "Test not found." });
        }

        let { Items: results } = await docClient.send(new ScanCommand({
            TableName: "TestifyResults",
            FilterExpression: "testId = :tid",
            ExpressionAttributeValues: { ":tid": testId }
        }));

        const { Items: allStudents } = await docClient.send(new ScanCommand({
            TableName: "TestifyUsers",
            FilterExpression: "#role = :student",
            ExpressionAttributeNames: {"#role": "role"},
            ExpressionAttributeValues: {":student": "Student"}
        }));

        let students = allStudents;
        if (req.user.role === 'Moderator') {
            students = allStudents.filter(s => req.user.assignedColleges.includes(s.college));
            const studentEmails = new Set(students.map(s => s.email));
            results = results.filter(r => studentEmails.has(r.studentEmail));
        }
        
        const studentMap = new Map(students.map(s => [s.email, { name: s.fullName, college: s.college }]));

        const reportResults = results.map(result => {
            const studentInfo = studentMap.get(result.studentEmail) || { name: 'Unknown', college: 'Unknown' };
            return {
                ...result, 
                studentName: studentInfo.name,
                college: studentInfo.college
            };
        });

        res.json({
            testTitle: test.title,
            results: reportResults
        });

    } catch (error) {
        console.error("Get Test Report Error:", error);
        res.status(500).json({ message: 'Server error fetching report data.' });
    }
});

app.get('/api/admin/passed-students/:testId', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    const { testId } = req.params;
    try {
        const { Items: passedResults } = await docClient.send(new ScanCommand({
            TableName: "TestifyResults",
            FilterExpression: "testId = :tid AND #res = :pass",
            ExpressionAttributeNames: { "#res": "result" },
            ExpressionAttributeValues: { ":tid": testId, ":pass": "Pass" }
        }));

        if (passedResults.length === 0) {
            return res.json([]);
        }

        const { Items: issuedCerts } = await docClient.send(new ScanCommand({
            TableName: "TestifyCertificates",
            FilterExpression: "testId = :tid",
            ExpressionAttributeValues: { ":tid": testId }
        }));
        const issuedEmails = new Set(issuedCerts.map(cert => cert.studentEmail));

        const eligibleStudents = passedResults.filter(result => !issuedEmails.has(result.studentEmail));

        res.json(eligibleStudents);
    } catch (error) {
        console.error("Get Passed Students Error:", error);
        res.status(500).json({ message: 'Server error.' });
    }
});

app.post('/api/admin/issue-certificates', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    const { testId, testTitle, passedStudents } = req.body;

    try {
        const uniqueStudentEmails = [...new Set(passedStudents.map(s => s.studentEmail))];
        if (uniqueStudentEmails.length === 0) {
            return res.status(400).json({ message: "No students to issue certificates to." });
        }

        const { Responses } = await docClient.send(new BatchGetCommand({
            RequestItems: { "TestifyUsers": { Keys: uniqueStudentEmails.map(email => ({ email })) } }
        }));
        const students = Responses.TestifyUsers || [];
        const studentMap = new Map(students.map(s => [s.email, s.fullName]));

        for (const result of passedStudents) {
            const studentName = studentMap.get(result.studentEmail) || 'Student';
            const issueDate = new Date().toLocaleDateString();
            const certificateId = uuidv4();

            await docClient.send(new PutCommand({
                TableName: "TestifyCertificates",
                Item: { certificateId, studentEmail: result.studentEmail, testId, testTitle, issuedAt: new Date().toISOString() }
            }));

            const mailOptions = {
    from: '"TESTIFY" <testifylearning.help@gmail.com>',
    to: result.studentEmail,
    subject: `Congratulations! You've earned a certificate for ${testTitle}`,
    html: `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>Certificate of Achievement</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap');
        body { font-family: 'Poppins', Arial, sans-serif; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }
        a { text-decoration: none; }
        @media screen and (max-width: 600px) {
            .content-width {
                width: 90% !important;
            }
        }
    </style>
</head>
<body style="background-color: #f3f4f6; margin: 0; padding: 0;">
    <!-- Preheader text for inbox preview -->
    <span style="display:none;font-size:1px;color:#ffffff;line-height:1px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;">
        Congratulations on earning your certificate!
    </span>
    <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #f3f4f6;">
        <tr>
            <td align="center" style="padding: 40px 20px;">
                <!-- Main Card -->
                <table class="content-width" width="600" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #ffffff; border-radius: 12px; box-shadow: 0 10px 30px -10px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td align="center" style="padding: 30px 40px 20px; border-bottom: 1px solid #e5e7eb;">
                            <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1756037774/Gemini_Generated_Image_eu0ib0eu0ib0eu0i_z0amjh.png" 
                                 alt="Testify Logo" style="height: 50px; width: auto;">
                        </td>
                    </tr>
                    
                    <!-- Content Body -->
                    <tr>
                        <td align="center" style="padding: 40px; text-align: center;">
                             <h1 style="font-family: 'Poppins', Arial, sans-serif; font-size: 26px; font-weight: 700; color: #111827; margin: 0 0 15px;">Certificate Earned!</h1>
                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 16px; color: #4b5563; margin: 0 0 30px; line-height: 1.7;">
                                 Congratulations, <b>${studentName}</b>! You've successfully passed the test for "<b>${testTitle}</b>". Your new certificate is waiting for you in your dashboard.
                             </p>
                             <a href="https://testify-io-ai.onrender.com/student/my-courses.html" 
                                target="_blank"
                                style="display: inline-block; padding: 15px 35px; font-family: 'Poppins', Arial, sans-serif; font-size: 16px; font-weight: 600; color: #ffffff; background-color: #4338ca; border-radius: 8px; text-decoration: none;">
                                 View My Certificate
                             </a>
                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 14px; color: #6b7280; margin: 30px 0 0;">
                                 Well done on your achievement!
                             </p>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td align="center" style="padding: 30px 40px; background-color: #f9fafb; border-top: 1px solid #e5e7eb; border-radius: 0 0 12px 12px;">
                            <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0 0 8px;">
                                &copy; ${new Date().getFullYear()} TESTIFY. All rights reserved.
                            </p>
                            <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0;">
                                Houston, TX, USA | <a href="mailto:testifylearning.help@gmail.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>`
};


           await sendEmailWithResend(mailOptions);
        }
        res.status(200).json({ message: `Successfully issued ${passedStudents.length} certificates.` });

    } catch (error) {
        console.error("Issue Certificates Error:", error);
        res.status(500).json({ message: 'Server error.' });
    }
});

app.get('/api/student/certificates', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    try {
        const { Items } = await docClient.send(new QueryCommand({
            TableName: "TestifyCertificates",
            IndexName: "StudentEmailIndex",
            KeyConditionExpression: "studentEmail = :email",
            ExpressionAttributeValues: { ":email": req.user.email }
        }));
        res.json(Items);
    } catch (error) {
        console.error("Get Student Certificates Error:", error);
        res.status(500).json({ message: 'Server error.' });
    }
});

app.get('/api/student/certificate/:id', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    const { id } = req.params;
    const studentEmail = req.user.email;
    try {
        const { Item: certificate } = await docClient.send(new GetCommand({
            TableName: "TestifyCertificates", Key: { certificateId: id }
        }));
        if (!certificate || certificate.studentEmail !== studentEmail) {
            return res.status(404).json({ message: "Certificate not found or access denied." });
        }
        const { Item: student } = await docClient.send(new GetCommand({
            TableName: "TestifyUsers", Key: { email: studentEmail }
        }));
        res.json({
            ...certificate,
            testTitle: certificate.courseTitle || certificate.testTitle,
            studentName: student ? student.fullName : 'Student',
            profileImageUrl: student ? student.profileImageUrl : null
        });
    } catch (error) {
        console.error("Get Single Certificate Error:", error);
        res.status(500).json({ message: 'Server error fetching certificate.' });
    }
});


app.get('/api/verify-certificate/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const { Item: certificate } = await docClient.send(new GetCommand({
            TableName: "TestifyCertificates",
            Key: { certificateId: id }
        }));

        if (!certificate) {
            return res.status(404).json({ message: "Certificate not found." });
        }

        const { Item: student } = await docClient.send(new GetCommand({
            TableName: "TestifyUsers",
            Key: { email: certificate.studentEmail }
        }));

       res.json({
            certificateId: certificate.certificateId,
            studentName: student ? student.fullName : 'Unknown Student',
            testTitle: certificate.testTitle,
            issuedAt: certificate.issuedAt,
            studentEmail: certificate.studentEmail,
            college: student ? student.college : 'N/A',
            rollNumber: student ? student.rollNumber : 'N/A',
            profileImageUrl: student ? student.profileImageUrl : null // Added this line
        });

    } catch (error) {
        console.error("Verify Certificate Error:", error);
        res.status(500).json({ message: 'Server error verifying certificate.' });
    }
});

app.post('/api/admin/generate-course-from-pdf', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }

    const { text } = req.body;
    if (!text) {
        return res.status(400).json({ message: 'No text provided from PDF.' });
    }

    try {
        const fetch = (await import('node-fetch')).default;

        const prompt = `Based on the following text from a course document, structure it into a JSON object for a learning platform. The JSON should have a main 'title', a brief 'description', and a list of 'modules'. Each module should have a 'title' and a list of 'subModules'. Each sub-module should have a 'title' and 'textContent'. Here is the text:\n\n${text}`;
        
        const schema = {
            type: "OBJECT",
            properties: {
                "title": { "type": "STRING" },
                "description": { "type": "STRING" },
                "modules": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "title": { "type": "STRING" },
                            "subModules": {
                                "type": "ARRAY",
                                "items": {
                                    "type": "OBJECT",
                                    "properties": {
                                        "title": { "type": "STRING" },
                                        "textContent": { "type": "STRING" }
                                    },
                                    "required": ["title", "textContent"]
                                }
                            }
                        },
                        "required": ["title", "subModules"]
                    }
                }
            },
            required: ["title", "description", "modules"]
        };

        const apiKey = 'AIzaSyAR_X4MZ75vxwV7OTU3dabFRcVe4SxWpb8';
        const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key=${apiKey}`;
        
        const payload = {
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: {
                responseMimeType: "application/json",
                responseSchema: schema
            }
        };

        const apiResponse = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!apiResponse.ok) {
            const errorBody = await apiResponse.text();
            console.error("Gemini API Error:", errorBody);
            throw new Error(`AI API call failed with status: ${apiResponse.status}`);
        }

        const result = await apiResponse.json();
        const jsonText = result.candidates[0].content.parts[0].text;
        const structuredCourse = JSON.parse(jsonText);

        res.json(structuredCourse);

    } catch (error) {
        console.error('Error in AI generation backend:', error);
        res.status(500).json({ message: 'Failed to generate course from AI.' });
    }
});
// =================================================================
// --- ADMIN & MODERATOR ROUTES FOR STUDENT MANAGEMENT ---
// =================================================================

app.get('/api/admin/students/:college', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    const { college } = req.params;

    if (req.user.role === 'Moderator' && !req.user.assignedColleges.includes(college)) {
        return res.status(403).json({ message: 'Access denied to this college.' });
    }

    try {
        const studentsResponse = await docClient.send(new ScanCommand({
            TableName: "TestifyUsers",
            FilterExpression: "college = :college AND #role = :student",
            ExpressionAttributeNames: { "#role": "role" },
            ExpressionAttributeValues: { ":college": college, ":student": "Student" }
        }));
        const students = studentsResponse.Items;

        const resultsResponse = await docClient.send(new ScanCommand({ TableName: "TestifyResults" }));
        const coursesResponse = await docClient.send(new ScanCommand({ TableName: "TestifyCourseProgress" }));

        const resultsByStudent = resultsResponse.Items.reduce((acc, result) => {
            (acc[result.studentEmail] = acc[result.studentEmail] || []).push(result);
            return acc;
        }, {});

        const coursesByStudent = coursesResponse.Items.reduce((acc, course) => {
            (acc[course.studentEmail] = acc[course.studentEmail] || []).push(course);
            return acc;
        }, {});

        const detailedStudents = students.map(student => ({
            ...student,
            tests: resultsByStudent[student.email] || [],
            courses: coursesByStudent[student.email] || []
        }));

        res.json(detailedStudents);
    } catch (error)  {
        console.error("Get Students by College Error:", error);
        res.status(500).json({ message: 'Server error fetching students.' });
    }
});


app.put('/api/admin/students/:email', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    const { email } = req.params;
    const { fullName, mobile, college, department, rollNumber } = req.body;
    
    try {
        if (req.user.role === 'Moderator') {
            const { Item: student } = await docClient.send(new GetCommand({ TableName: "TestifyUsers", Key: { email } }));
            if (!student || !req.user.assignedColleges.includes(student.college)) {
                return res.status(403).json({ message: 'You do not have permission to edit this student.' });
            }
        }

        await docClient.send(new UpdateCommand({
            TableName: "TestifyUsers",
            Key: { email },
            UpdateExpression: "set fullName = :fn, mobile = :m, college = :c, department = :d, rollNumber = :rn",
            ExpressionAttributeValues: {
                ":fn": fullName,
                ":m": mobile,
                ":c": college,
                ":d": department,
                ":rn": rollNumber
            }
        }));
        res.json({ message: 'Student updated successfully.' });
    } catch (error) {
        console.error("Update Student Error:", error);
        res.status(500).json({ message: 'Server error updating student.' });
    }
});

app.post('/api/admin/student/:email/image', authMiddleware, adminOrModeratorAuth, upload.single('profileImage'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No image file uploaded.' });
    }

    const { email } = req.params;

    try {
        const { Item: student } = await docClient.send(new GetCommand({
            TableName: "TestifyUsers",
            Key: { email }
        }));

        if (!student) {
            return res.status(404).json({ message: 'Student not found.' });
        }

        if (req.user.role === 'Moderator' && !req.user.assignedColleges.includes(student.college)) {
            return res.status(403).json({ message: 'You do not have permission to change this student\'s image.' });
        }

        const b64 = Buffer.from(req.file.buffer).toString("base64");
        let dataURI = "data:" + req.file.mimetype + ";base64," + b64;
        const result = await cloudinary.uploader.upload(dataURI, {
            folder: "profile_pictures"
        });

        await docClient.send(new UpdateCommand({
            TableName: "TestifyUsers",
            Key: { email },
            UpdateExpression: "set profileImageUrl = :url",
            ExpressionAttributeValues: {
                ":url": result.secure_url
            }
        }));

        res.json({ message: `Image for ${email} updated successfully.`, imageUrl: result.secure_url });

    } catch (error) {
        console.error("Admin/Moderator Image Upload Error:", error);
        res.status(500).json({ message: 'Server error uploading image.' });
    }
});


app.delete('/api/admin/students/:email', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { email } = req.params;
    try {
        await docClient.send(new DeleteCommand({
            TableName: "TestifyUsers",
            Key: { email }
        }));
        res.json({ message: 'Student deleted successfully.' });
    } catch (error) {
        console.error("Delete Student Error:", error);
        res.status(500).json({ message: 'Server error deleting student.' });
    }
});

app.patch('/api/admin/students/:email/status', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    const { email } = req.params;
    const { isBlocked } = req.body;
    try {
        if (req.user.role === 'Moderator') {
            const { Item: student } = await docClient.send(new GetCommand({ TableName: "TestifyUsers", Key: { email } }));
            if (!student || !req.user.assignedColleges.includes(student.college)) {
                return res.status(403).json({ message: 'You do not have permission to block/unblock this student.' });
            }
        }

        await docClient.send(new UpdateCommand({
            TableName: "TestifyUsers",
            Key: { email },
            UpdateExpression: "set isBlocked = :isBlocked",
            ExpressionAttributeValues: { ":isBlocked": isBlocked }
        }));
        res.json({ message: `Student has been ${isBlocked ? 'blocked' : 'unblocked'}.` });
    } catch (error) {
        console.error("Block/Unblock Student Error:", error);
        res.status(500).json({ message: 'Server error updating student status.' });
    }
});

app.post('/api/student/face-verification', authMiddleware, async (req, res) => {
    const { profileImageUrl, webcamImage } = req.body;

    if (!profileImageUrl || !webcamImage) {
        return res.status(400).json({ message: 'Missing required image data.' });
    }

    try {
        const profileImageResponse = await fetch(profileImageUrl);
        if (!profileImageResponse.ok) {
            throw new Error('Failed to download profile image from Cloudinary.');
        }
        const profileImageBuffer = await profileImageResponse.buffer();
        const webcamImageBuffer = Buffer.from(webcamImage.replace(/^data:image\/jpeg;base64,/, ""), 'base64');

        const command = new CompareFacesCommand({
            SourceImage: {
                Bytes: profileImageBuffer,
            },
            TargetImage: {
                Bytes: webcamImageBuffer,
            },
            SimilarityThreshold: 90,
        });

        const response = await rekognitionClient.send(command);

        if (response.FaceMatches && response.FaceMatches.length > 0) {
            const confidence = response.FaceMatches[0].Similarity;
            res.json({ success: true, message: 'Face verification successful.', confidence });
        } else {
            res.status(401).json({ success: false, message: 'Face verification failed. The person in the camera does not match the profile image.' });
        }

    } catch (error) {
        console.error('Face Verification Error:', error);
        res.status(500).json({ message: 'An error occurred during face verification.' });
    }
});
app.get('/api/admin/all-students', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    try {
        let filterExpression = "#role = :student";
        let expressionAttributeValues = { ":student": "Student" };
        
        if (req.user.role === 'Moderator') {
            if (req.user.assignedColleges.length === 0) {
                return res.json([]);
            }
            filterExpression += ' AND (' + req.user.assignedColleges.map((_, i) => `college = :c${i}`).join(' OR ') + ')';
            req.user.assignedColleges.forEach((college, i) => {
                expressionAttributeValues[`:c${i}`] = college;
            });
        }

        const studentsResponse = await docClient.send(new ScanCommand({
            TableName: "TestifyUsers",
            FilterExpression: filterExpression,
            ExpressionAttributeNames: {"#role": "role"},
            ExpressionAttributeValues: expressionAttributeValues
        }));
        const students = studentsResponse.Items;

        const resultsResponse = await docClient.send(new ScanCommand({ TableName: "TestifyResults" }));
        const coursesResponse = await docClient.send(new ScanCommand({ TableName: "TestifyCourseProgress" }));

        const resultsByStudent = resultsResponse.Items.reduce((acc, result) => {
            (acc[result.studentEmail] = acc[result.studentEmail] || []).push(result);
            return acc;
        }, {});

        const coursesByStudent = coursesResponse.Items.reduce((acc, course) => {
            (acc[course.studentEmail] = acc[course.studentEmail] || []).push(course);
            return acc;
        }, {});

        const detailedStudents = students.map(student => ({
            ...student,
            tests: resultsByStudent[student.email] || [],
            courses: coursesByStudent[student.email] || []
        }));

        res.json(detailedStudents);
    } catch (error) {
        console.error("Get All Students Error:", error);
        res.status(500).json({ message: 'Server error fetching all students.' });
    }
});


app.get('/api/admin/students', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    const { college, year, department } = req.query;

    if (!college) {
        return res.status(400).json({ message: 'College filter is required.' });
    }

    if (req.user.role === 'Moderator' && !req.user.assignedColleges.includes(college)) {
        return res.status(403).json({ message: 'Access denied to this college.' });
    }

    try {
        let filterExpression = "college = :college AND #role = :student";
        const expressionAttributeValues = {
            ":college": college,
            ":student": "Student"
        };
        const expressionAttributeNames = {
            "#role": "role"
        };

        if (year && year !== 'All') {
            filterExpression += " AND #year = :year";
            expressionAttributeValues[":year"] = year;
            expressionAttributeNames["#year"] = "year";
        }
        
        if (department && department !== 'All') {
            filterExpression += " AND department = :department";
            expressionAttributeValues[":department"] = department;
        }

        const params = {
            TableName: "TestifyUsers",
            FilterExpression: filterExpression,
            ExpressionAttributeValues: expressionAttributeValues,
            ExpressionAttributeNames: expressionAttributeNames
        };

        const studentsResponse = await docClient.send(new ScanCommand(params));
        const students = studentsResponse.Items;
        
        res.json(students);
        
    } catch (error) {
        console.error("Get Filtered Students Error:", error);
        res.status(500).json({ message: 'Server error fetching filtered students.' });
    }
});


// =================================================================
// --- NEW: IMPACT STATS ROUTES ---
// =================================================================

app.get('/api/impact-stats', async (req, res) => {
    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: "TestifyUsers",
            Key: { email: "_system_impact_stats" }
        }));
        
        if (Item) {
            res.json({
                institutions: Item.institutions,
                exams: Item.exams,
                uptime: Item.uptime,
                flyerImageUrl: Item.flyerImageUrl || null
            });
        } else {
            res.json({ institutions: "0+", exams: "0+", uptime: "0%", flyerImageUrl: null });
        }
    } catch (error) {
        console.error("Get Impact Stats Error:", error);
        res.status(500).json({ message: 'Server error fetching stats.' });
    }
});

app.post('/api/admin/impact-stats', authMiddleware, upload.single('flyerImage'), async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    
    const { institutions, exams, uptime } = req.body;
    let flyerImageUrl;

    try {
        const { Item: existingStats } = await docClient.send(new GetCommand({
            TableName: "TestifyUsers",
            Key: { email: "_system_impact_stats" }
        }));

        if (req.file) {
            const b64 = Buffer.from(req.file.buffer).toString("base64");
            const dataURI = "data:" + req.file.mimetype + ";base64," + b64;
            const result = await cloudinary.uploader.upload(dataURI, {
                folder: "flyers"
            });
            flyerImageUrl = result.secure_url;
        } else {
            flyerImageUrl = existingStats ? existingStats.flyerImageUrl : null;
        }

        const statsData = {
            email: "_system_impact_stats",
            recordType: "ImpactStats",
            institutions,
            exams,
            uptime,
            flyerImageUrl
        };

        await docClient.send(new PutCommand({
            TableName: "TestifyUsers",
            Item: statsData
        }));
        
        res.status(200).json({ message: 'Impact stats and flyer updated successfully!' });

    } catch (error) {
        console.error("Update Impact Stats Error:", error);
        res.status(500).json({ message: 'Server error updating stats.' });
    }
});

// =================================================================
// --- COMPILER ENDPOINT (REVISED WITH JUDGE0) ---
// =================================================================
app.post('/api/compile', authMiddleware, async (req, res) => {
    const { language, code, input } = req.body;

    // IMPORTANT: Replace with your actual RapidAPI Key for OneCompiler
    // It's best to store this in an environment variable (.env file) for security
    const ONECOMPILER_API_KEY = process.env.ONECOMPILER_API_KEY || '09ccf0b69bmsh066f3a3bc867b99p178664jsna5e9720da3f6';

    if (!language || !code) {
        return res.status(400).json({ message: 'Language and code are required.' });
    }
    if (!ONECOMPILER_API_KEY || ONECOMPILER_API_KEY === 'YOUR_ONECOMPILER_RAPIDAPI_KEY') {
         return res.status(500).json({ message: 'OneCompiler API key is not configured on the server.' });
    }

    // Map your language names to OneCompiler's language identifiers
    const languageMap = {
        'c': 'c',
        'cpp': 'cpp',
        'java': 'java',
        'python': 'python'
    };
    
    // Determine the main file name based on language
    const fileNames = {
        'c': 'main.c',
        'cpp': 'main.cpp',
        'java': 'Main.java',
        'python': 'main.py'
    };

    const langIdentifier = languageMap[language];
    const fileName = fileNames[language];

    if (!langIdentifier) {
        return res.status(400).json({ message: `Language '${language}' is not supported.` });
    }

    try {
        const submissionPayload = {
            language: langIdentifier,
            stdin: input || "",
            files: [
                {
                    name: fileName,
                    content: code
                }
            ]
        };

        const submissionResponse = await fetch('https://onecompiler-apis.p.rapidapi.com/api/v1/run', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-RapidAPI-Key': ONECOMPILER_API_KEY,
                'X-RapidAPI-Host': 'onecompiler-apis.p.rapidapi.com'
            },
            body: JSON.stringify(submissionPayload)
        });

        if (!submissionResponse.ok) {
            const errorBody = await submissionResponse.text();
            console.error("OneCompiler API Error:", errorBody);
            return res.status(500).json({ message: 'Error communicating with the compilation service.' });
        }

        const result = await submissionResponse.json();
        
        // Combine stdout and stderr for the output
        let output = result.stdout || '';
        if (result.stderr) {
            output += `\nError:\n${result.stderr}`;
        }
        if (result.exception) {
            output += `\nException:\n${result.exception}`;
        }


        res.json({ output: output || 'No output.' });

    } catch (error) {
        console.error("Compile Error:", error);
        res.status(500).json({ message: 'Server error during compilation.' });
    }
});


app.post('/api/admin/practice-tests', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { testTitle, questions } = req.body;
    const testId = uuidv4();

    const newPracticeTest = {
        testId,
        title: testTitle,
        questions,
        createdAt: new Date().toISOString(),
    };

    try {
        await docClient.send(new PutCommand({ TableName: "TestifyPracticeTests", Item: newPracticeTest }));
        res.status(201).json({ message: 'Practice test created successfully!', test: newPracticeTest });
    } catch (error) {
        console.error("Create Practice Test Error:", error);
        res.status(500).json({ message: 'Server error creating practice test.' });
    }
});

app.get('/api/admin/practice-tests', authMiddleware, async (req, res) => {
     if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    try {
        const { Items } = await docClient.send(new ScanCommand({ TableName: "TestifyPracticeTests" }));
        res.json(Items);
    } catch (error) {
        console.error("Get Practice Tests Error:", error);
        res.status(500).json({ message: 'Server error fetching practice tests.' });
    }
});

app.post('/api/admin/assign-practice-test', authMiddleware, async (req, res) => {
     if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { testId, colleges } = req.body;

    try {
        for (const college of colleges) {
            const assignmentId = uuidv4();
            const assignment = {
                assignmentId,
                testId,
                college,
                assignedAt: new Date().toISOString()
            };
            await docClient.send(new PutCommand({ TableName: "TestifyPracticeAssignments", Item: assignment }));
        }
        res.status(200).json({ message: 'Practice test assigned successfully!' });
    } catch (error) {
        console.error("Assign Practice Test Error:", error);
        res.status(500).json({ message: 'Server error assigning practice test.' });
    }
});

app.get('/api/student/practice-tests', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    
    try {
        const studentCollege = req.user.college;
        if (!studentCollege) return res.json([]);

        const assignmentsResponse = await docClient.send(new ScanCommand({
            TableName: "TestifyPracticeAssignments",
            FilterExpression: "college = :c",
            ExpressionAttributeValues: { ":c": studentCollege }
        }));
        
        const assignedTestIds = assignmentsResponse.Items.map(a => a.testId);
        if (assignedTestIds.length === 0) return res.json([]);

        const uniqueTestIds = [...new Set(assignedTestIds)];
        const keys = uniqueTestIds.map(testId => ({ testId }));
        
        const testsResponse = await docClient.send(new BatchGetCommand({
            RequestItems: { "TestifyPracticeTests": { Keys: keys } }
        }));
        
        res.json(testsResponse.Responses.TestifyPracticeTests || []);

    } catch (error) {
        console.error("Get Student Practice Tests Error:", error);
        res.status(500).json({ message: 'Server error fetching practice tests.' });
    }
});

app.post('/api/student/submit-practice-test', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    
    const { testId, answers } = req.body;

    try {
        const { Item: test } = await docClient.send(new GetCommand({
            TableName: "TestifyPracticeTests",
            Key: { testId }
        }));

        if (!test) return res.status(404).json({ message: "Practice test not found." });

        let score = 0;
        let totalMarks = 0;
        test.questions.forEach((question, index) => {
            const studentAnswer = answers[index];
            totalMarks += (question.marks || 1);
            if (studentAnswer === null || studentAnswer === undefined) return;

            if (question.type === 'mcq-single' || question.type === 'fill-blank') {
                if (String(studentAnswer).trim().toLowerCase() === String(question.correctAnswer).trim().toLowerCase()) {
                    score += (question.marks || 1);
                }
            } else if (question.type === 'mcq-multiple') {
                const correctAnswers = new Set(question.correctAnswers);
                const studentAnswersSet = new Set(studentAnswer);
                if (correctAnswers.size === studentAnswersSet.size && [...correctAnswers].every(val => studentAnswersSet.has(val))) {
                     score += (question.marks || 1);
                }
            }
        });

        const percentageScore = totalMarks > 0 ? Math.round((score / totalMarks) * 100) : 0;

        res.status(200).json({ 
            message: 'Practice test submitted!',
            score: score,
            totalMarks: totalMarks,
            percentage: percentageScore
        });

    } catch (error) {
        console.error("Submit Practice Test Error:", error);
        res.status(500).json({ message: 'Server error submitting practice test.' });
    }
});

app.post('/api/unassign-test', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    const { testId, colleges, studentEmails } = req.body;

    if (!testId || (!colleges && !studentEmails)) {
        return res.status(400).json({ message: 'Test ID and either colleges or student emails are required.' });
    }

    try {
        let assignmentsToDelete = [];
        let emailsToProcess = [];

        if (studentEmails && studentEmails.length > 0) {
            emailsToProcess = studentEmails;
        } else if (colleges && colleges.length > 0) {
            if (req.user.role === 'Moderator') {
                const isAllowed = colleges.every(college => req.user.assignedColleges.includes(college));
                if (!isAllowed) {
                    return res.status(403).json({ message: 'You can only un-assign tests from your assigned colleges.' });
                }
            }

            const collegeStudentFilter = colleges.map((_, index) => `college = :c${index}`).join(' OR ');
            const collegeStudentValues = {};
            colleges.forEach((college, index) => {
                collegeStudentValues[`:c${index}`] = college;
            });

            const { Items: studentsInColleges } = await docClient.send(new ScanCommand({
                TableName: "TestifyUsers",
                FilterExpression: collegeStudentFilter,
                ExpressionAttributeValues: collegeStudentValues,
                ProjectionExpression: "email"
            }));
            
            emailsToProcess = studentsInColleges.map(s => s.email);
        }

        if (emailsToProcess.length === 0) {
            return res.status(200).json({ message: 'No matching assignments found to remove.' });
        }

        const emailFilters = emailsToProcess.map((_, index) => `:email${index}`).join(', ');
        const expressionAttributeValues = { ":tid": testId };
        emailsToProcess.forEach((email, index) => {
            expressionAttributeValues[`:email${index}`] = email;
        });

        const scanParams = {
            TableName: "TestifyAssignments",
            FilterExpression: `testId = :tid AND studentEmail IN (${emailFilters})`,
            ExpressionAttributeValues: expressionAttributeValues,
            ProjectionExpression: "assignmentId"
        };

        const { Items } = await docClient.send(new ScanCommand(scanParams));
        assignmentsToDelete = Items;
        
        if (assignmentsToDelete.length === 0) {
            return res.status(200).json({ message: 'No matching assignments found to remove.' });
        }

        const deleteRequests = assignmentsToDelete.map(item => ({
            DeleteRequest: { Key: { assignmentId: item.assignmentId } }
        }));

        const batches = [];
        for (let i = 0; i < deleteRequests.length; i += 25) {
            batches.push(deleteRequests.slice(i, i + 25));
        }

        for (const batch of batches) {
            await docClient.send(new BatchWriteCommand({
                RequestItems: { "TestifyAssignments": batch }
            }));
        }

        res.status(200).json({ message: `Successfully removed ${assignmentsToDelete.length} assignments.` });

    } catch (error) {
        console.error("Un-assign Test Error:", error);
        res.status(500).json({ message: 'Server error while un-assigning test.' });
    }
});

app.get('/api/admin/assignment-report', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    const { testId, courseId } = req.query;

    if (!testId && !courseId) {
        return res.status(400).json({ message: 'A testId or courseId is required.' });
    }

    try {
        let assignments = [];
        let studentEmails = new Set();

        if (testId) {
            const { Items } = await docClient.send(new ScanCommand({
                TableName: "TestifyAssignments",
                FilterExpression: "testId = :tid",
                ExpressionAttributeValues: { ":tid": testId }
            }));
            assignments = Items.map(item => ({
                studentEmail: item.studentEmail,
                assignedAt: item.assignedAt
            }));
            Items.forEach(item => studentEmails.add(item.studentEmail));
        } else if (courseId) {
            const { Items } = await docClient.send(new ScanCommand({
                TableName: "TestifyCourseProgress",
                FilterExpression: "courseId = :cid",
                ExpressionAttributeValues: { ":cid": courseId }
            }));
            assignments = Items.map(item => ({
                studentEmail: item.studentEmail,
                assignedAt: item.assignedAt
            }));
            Items.forEach(item => studentEmails.add(item.studentEmail));
        }

        if (studentEmails.size === 0) {
            return res.json([]);
        }

        const studentEmailArray = Array.from(studentEmails).filter(email => email && typeof email === 'string');

        if (studentEmailArray.length === 0) {
            return res.json([]);
        }

        const keys = studentEmailArray.map(email => ({ email }));
        
        const { Responses } = await docClient.send(new BatchGetCommand({
            RequestItems: { "TestifyUsers": { Keys: keys } }
        }));
        let students = Responses.TestifyUsers || [];
        
        if (req.user.role === 'Moderator') {
            const allowedColleges = new Set(req.user.assignedColleges);
            students = students.filter(student => allowedColleges.has(student.college));
        }
        
        const studentMap = new Map(students.map(s => [s.email, { fullName: s.fullName, college: s.college }]));

        const finalReport = assignments
            .map(assignment => {
                const studentInfo = studentMap.get(assignment.studentEmail);
                if (studentInfo) {
                    return {
                        ...assignment,
                        studentName: studentInfo.fullName,
                        college: studentInfo.college
                    };
                }
                return null;
            })
            .filter(Boolean);

        res.json(finalReport);

    } catch (error) {
        console.error("Get Assignment Report Error:", error);
        res.status(500).json({ message: 'Server error fetching assignment report.' });
    }
});

//////////////////////////////////////////////////////////////////////////////////interview part
app.post('/api/admin/interviews', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { title, questions } = req.body;
    if (!title || !questions || !Array.isArray(questions) || questions.length === 0) {
        return res.status(400).json({ message: 'Title and at least one question are required.' });
    }
    const interviewId = uuidv4();
    const newInterview = {
        PK: `INTERVIEW#${interviewId}`,
        SK: `METADATA`,
        interviewId,
        title,
        questions,
        createdAt: new Date().toISOString(),
    };
    try {
        await docClient.send(new PutCommand({ TableName: "TestifyInterviews", Item: newInterview }));
        res.status(201).json({ message: 'Interview created successfully!', interview: newInterview });
    } catch (error) {
        console.error("Create Interview Error:", error);
        res.status(500).json({ message: 'Server error creating interview.' });
    }
});

app.get('/api/admin/interviews', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyInterviews",
            FilterExpression: "SK = :sk",
            ExpressionAttributeValues: { ":sk": "METADATA" }
        }));
        res.json(Items);
    } catch (error) {
        console.error("Get Interviews Error:", error);
        res.status(500).json({ message: 'Server error fetching interviews.' });
    }
});

app.post('/api/admin/assign-interview', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    const { interviewId, colleges, studentEmails } = req.body;
    if (!interviewId) {
        return res.status(400).json({ message: 'Interview ID is required.' });
    }

    try {
        let studentsToNotify = [];

        if (studentEmails && studentEmails.length > 0) {
            studentsToNotify = studentEmails.map(email => email.trim()).filter(Boolean);
        } else if (colleges && colleges.length > 0) {
            const filterExpression = colleges.map((_, index) => `college = :c${index}`).join(' OR ');
            const expressionAttributeValues = {};
            colleges.forEach((college, index) => {
                expressionAttributeValues[`:c${index}`] = college;
            });
            const { Items } = await docClient.send(new ScanCommand({
                TableName: "TestifyUsers",
                FilterExpression: filterExpression,
                ExpressionAttributeValues: expressionAttributeValues,
                ProjectionExpression: "email"
            }));
            studentsToNotify = Items.map(s => s.email);
        }

        if (studentsToNotify.length === 0) {
             return res.status(400).json({ message: "No students found to assign." });
        }

        const assignments = studentsToNotify.map(email => ({
            PutRequest: {
                Item: {
                    PK: `ASSIGNMENT#${interviewId}`,
                    SK: `STUDENT#${email}`,
                    GSI1PK: `STUDENT#${email}`,
                    GSI1SK: `ASSIGNMENT#${interviewId}`,
                    interviewId,
                    studentEmail: email,
                    assignedAt: new Date().toISOString()
                }
            }
        }));

        const batches = [];
        for (let i = 0; i < assignments.length; i += 25) {
            batches.push(assignments.slice(i, i + 25));
        }

        for (const batch of batches) {
            await docClient.send(new BatchWriteCommand({
                RequestItems: { "TestifyInterviews": batch }
            }));
        }

        res.status(200).json({ message: `Interview assigned to ${studentsToNotify.length} students successfully!` });

    } catch (error) {
        console.error("Assign Interview Error:", error);
        res.status(500).json({ message: 'Server error assigning interview.' });
    }
});

app.get('/api/student/interviews', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    try {
        const { Items: assignments } = await docClient.send(new QueryCommand({
            TableName: "TestifyInterviews",
            IndexName: "GSI1",
            KeyConditionExpression: "GSI1PK = :gsi1pk",
            ExpressionAttributeValues: { ":gsi1pk": `STUDENT#${req.user.email}` }
        }));
        
        if (!assignments || assignments.length === 0) {
            return res.json([]);
        }
        
        const interviewIds = [...new Set(assignments.map(a => a.interviewId))];
        
        const keys = interviewIds.map(id => ({ 
            PK: `INTERVIEW#${id}`, 
            SK: 'METADATA' 
        }));

        const { Responses } = await docClient.send(new BatchGetCommand({
            RequestItems: { "TestifyInterviews": { Keys: keys } }
        }));
        
        res.json(Responses.TestifyInterviews || []);

    } catch (error) {
        console.error("Get Student Interviews Error:", error);
        res.status(500).json({ message: 'Server error fetching interviews.' });
    }
});

app.post('/api/student/submit-interview', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    
    const { interviewId, answers, violationReason } = req.body;
    const studentEmail = req.user.email;
    const resultId = uuidv4();

    try {
        const { Item: interview } = await docClient.send(new GetCommand({
            TableName: "TestifyInterviews",
            Key: { PK: `INTERVIEW#${interviewId}`, SK: 'METADATA' }
        }));
        
        if (!interview) {
            return res.status(404).json({ message: 'Interview definition not found.' });
        }

        let questionScore = 0;
        const processedAnswers = answers.map(ans => {
            const originalQuestion = interview.questions.find(q => q.questionText === ans.questionText);
            const isCorrect = originalQuestion && ans.studentAnswerText.toLowerCase().includes(originalQuestion.correctAnswer.toLowerCase());
            if (isCorrect) {
                questionScore += 1;
            }
            return { ...ans, isCorrect };
        });

        const fluencyMarks = 5.0; 
        const sittingMarks = 5.0;
        const totalScore = questionScore + fluencyMarks + sittingMarks;

        const newResult = {
            PK: `RESULT#${interviewId}`,
            SK: `STUDENT#${studentEmail}`,
            GSI1PK: `INTERVIEW#${interviewId}`,
            GSI1SK: `RESULT#${resultId}`,
            GSI2PK: `STUDENT#${studentEmail}`,
            GSI2SK: `RESULT#${interviewId}`,
            interviewId,
            studentEmail,
            answers: processedAnswers,
            fluencyMarks,
            sittingMarks,
            score: totalScore,
            violationReason,
            resultsPublished: false,
            submittedAt: new Date().toISOString(),
        };
        
        await docClient.send(new PutCommand({ TableName: "TestifyInterviews", Item: newResult }));
        res.status(201).json({ message: 'Interview submitted successfully! Your results will be available after review.' });

    } catch (error) {
        console.error("Submit Interview Error:", error);
        res.status(500).json({ message: 'Server error submitting interview.' });
    }
});

app.get('/api/admin/interview-report/:interviewId', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    const { interviewId } = req.params;
    try {
        const { Item: interview } = await docClient.send(new GetCommand({
            TableName: "TestifyInterviews",
            Key: { PK: `INTERVIEW#${interviewId}`, SK: 'METADATA' }
        }));

        if (!interview) {
            return res.status(404).json({ message: "Interview not found." });
        }
        
        const { Items: results } = await docClient.send(new QueryCommand({
            TableName: "TestifyInterviews",
            IndexName: "GSI1",
            KeyConditionExpression: "GSI1PK = :gsi1pk",
            FilterExpression: "begins_with(GSI1SK, :gsi1sk)",
            ExpressionAttributeValues: { 
                ":gsi1pk": `INTERVIEW#${interviewId}`,
                ":gsi1sk": "RESULT#"
            }
        }));

        const studentEmails = [...new Set(results.map(r => r.studentEmail))];
        if (studentEmails.length === 0) {
            return res.json({ title: interview.title, results: [] });
        }

        const keys = studentEmails.map(email => ({ email }));
        const { Responses } = await docClient.send(new BatchGetCommand({
            RequestItems: { "TestifyUsers": { Keys: keys } }
        }));
        const students = Responses.TestifyUsers || [];
        const studentMap = new Map(students.map(s => [s.email, { fullName: s.fullName, college: s.college }]));

        const reportResults = results.map(result => {
            const studentInfo = studentMap.get(result.studentEmail) || { fullName: 'Unknown', college: 'Unknown' };
            return {
                ...result, 
                studentName: studentInfo.fullName,
                college: studentInfo.college
            };
        });

        res.json({
            title: interview.title,
            results: reportResults
        });

    } catch (error) {
        console.error("Get Interview Report Error:", error);
        res.status(500).json({ message: 'Server error fetching report.' });
    }
});

app.post('/api/admin/generate-interview-from-file', authMiddleware, upload.single('file'), async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded.' });
    }

    try {
        const data = await pdf(req.file.buffer);
        const text = data.text;
        if (!text) {
             return res.status(400).json({ message: 'Could not extract text from the uploaded file.' });
        }
        
        const fetch = (await import('node-fetch')).default;

        const prompt = `Based on the following text, create a structured JSON object for an interview. The JSON must have an array of 'questions'. Each question object in the array must have 'questionText' (string) and 'correctAnswer' (string, for the interviewer's reference). Here is the text:\n\n${text}`;
        const schema = {
            type: "OBJECT",
            properties: {
                "questions": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "questionText": { "type": "STRING" },
                            "correctAnswer": { "type": "STRING" }
                        },
                        "required": ["questionText", "correctAnswer"]
                    }
                }
            },
            required: ["questions"]
        };

        const apiKey = 'AIzaSyAR_X4MZ75vxwV7OTU3dabFRcVe4SxWpb8';
        const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key=${apiKey}`;
        const payload = {
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: { responseMimeType: "application/json", responseSchema: schema }
        };

        const apiResponse = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!apiResponse.ok) {
            const errorBody = await apiResponse.text();
            console.error("Gemini API Error:", errorBody);
            return res.status(502).json({ message: 'AI API call failed. Please check the backend logs.'});
        }

        const result = await apiResponse.json();
        const jsonText = result.candidates[0].content.parts[0].text;
        const structuredResponse = JSON.parse(jsonText);

        res.json(structuredResponse);

    } catch (error) {
        console.error('Error generating interview from text:', error);
        res.status(500).json({ message: 'Failed to generate interview from file due to a server error.' });
    }
});

app.get('/api/student/interviews/:id', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') {
        return res.status(403).json({ message: 'Access denied.' });
    }

    const { id: interviewId } = req.params;
    const studentEmail = req.user.email;

    try {
        const assignmentCheck = await docClient.send(new GetCommand({
            TableName: "TestifyInterviews",
            Key: {
                PK: `ASSIGNMENT#${interviewId}`,
                SK: `STUDENT#${studentEmail}`
            }
        }));

        if (!assignmentCheck.Item) {
            return res.status(403).json({ message: "Access denied. You are not assigned to this interview." });
        }

        const { Item: interviewDetails } = await docClient.send(new GetCommand({
            TableName: "TestifyInterviews",
            Key: {
                PK: `INTERVIEW#${interviewId}`,
                SK: 'METADATA'
            }
        }));

        if (!interviewDetails) {
            return res.status(404).json({ message: "Interview details not found." });
        }

        res.json(interviewDetails);

    } catch (error) {
        console.error("Get Single Student Interview Error:", error);
        res.status(500).json({ message: 'Server error fetching interview details.' });
    }
});

app.post('/api/admin/publish-interview-results', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    const { interviewId, studentEmail } = req.body;
    
    try {
        await docClient.send(new UpdateCommand({
            TableName: "TestifyInterviews",
            Key: {
                PK: `RESULT#${interviewId}`,
                SK: `STUDENT#${studentEmail}`
            },
            UpdateExpression: "set resultsPublished = :true",
            ExpressionAttributeValues: {
                ":true": true
            }
        }));
        res.status(200).json({ message: "Results published successfully for the student." });
    } catch (error) {
        console.error("Publish Interview Results Error:", error);
        res.status(500).json({ message: 'Server error publishing results.' });
    }
});

app.get('/api/student/interview-results', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    try {
        const { Items } = await docClient.send(new QueryCommand({
            TableName: "TestifyInterviews",
            IndexName: "GSI2",
            KeyConditionExpression: "GSI2PK = :gsi2pk",
            ExpressionAttributeValues: { ":gsi2pk": `STUDENT#${req.user.email}` }
        }));
        res.json(Items || []);
    } catch (error) {
        console.error("Get Student Interview Results Error:", error);
        res.status(500).json({ message: 'Server error fetching interview results.' });
    }
});

// --- NEW ENDPOINT: Request Password Reset ---
app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ message: 'Email is required.' });
    }

    try {
        const emailLower = email.toLowerCase();
        const { Item } = await docClient.send(new GetCommand({ TableName: "TestifyUsers", Key: { email: emailLower } }));

        if (!Item) {
            return res.status(404).json({ message: 'User not found. Please check your email address.' });
        }

        const resetToken = uuidv4();
        const resetTokenExpiry = Date.now() + 3600000; // 1 hour expiration

        await docClient.send(new UpdateCommand({
            TableName: "TestifyUsers",
            Key: { email: emailLower },
            UpdateExpression: "set resetToken = :token, resetTokenExpiry = :expiry",
            ExpressionAttributeValues: { ":token": resetToken, ":expiry": resetTokenExpiry }
        }));

        const appBaseUrl = req.headers.origin || 'http://localhost:3000';
const resetLink = `${appBaseUrl}/reset-password.html?token=${resetToken}&email=${email}`;

const mailOptions = {
    from: '"TESTIFY" <testifylearning.help@gmail.com>',
    to: email,
    subject: 'Password Reset Request',
    html: `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>Password Reset Request</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap');
        body { font-family: 'Poppins', Arial, sans-serif; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }
        a { text-decoration: none; }
        @media screen and (max-width: 600px) {
            .content-width {
                width: 90% !important;
            }
        }
    </style>
</head>
<body style="background-color: #f3f4f6; margin: 0; padding: 0;">
    <!-- Preheader text for inbox preview -->
    <span style="display:none;font-size:1px;color:#ffffff;line-height:1px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;">
        A request to reset your password was received.
    </span>
    <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #f3f4f6;">
        <tr>
            <td align="center" style="padding: 40px 20px;">
                <!-- Main Card -->
                <table class="content-width" width="600" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #ffffff; border-radius: 12px; box-shadow: 0 10px 30px -10px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td align="center" style="padding: 30px 40px 20px; border-bottom: 1px solid #e5e7eb;">
                            <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1756037774/Gemini_Generated_Image_eu0ib0eu0ib0eu0i_z0amjh.png" 
                                 alt="Testify Logo" style="height: 50px; width: auto;">
                        </td>
                    </tr>
                    
                    <!-- Content Body -->
                    <tr>
                        <td align="center" style="padding: 40px; text-align: center;">
                             <h1 style="font-family: 'Poppins', Arial, sans-serif; font-size: 26px; font-weight: 700; color: #111827; margin: 0 0 15px;">Password Reset Request</h1>
                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 16px; color: #4b5563; margin: 0 0 30px; line-height: 1.7;">
                                 We received a request to reset your password. Click the button below to set a new one. This link is valid for 1 hour.
                             </p>
                             <a href="${resetLink}" 
                                target="_blank"
                                style="display: inline-block; padding: 15px 35px; font-family: 'Poppins', Arial, sans-serif; font-size: 16px; font-weight: 600; color: #ffffff; background-color: #3b82f6; border-radius: 8px; text-decoration: none;">
                                 Reset Password
                             </a>
                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 14px; color: #6b7280; margin: 30px 0 0;">
                                 If you didn't request this, you can safely ignore this email.
                             </p>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td align="center" style="padding: 30px 40px; background-color: #f9fafb; border-top: 1px solid #e5e7eb; border-radius: 0 0 12px 12px;">
                            <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0 0 8px;">
                                &copy; ${new Date().getFullYear()} TESTIFY. All rights reserved.
                            </p>
                            <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0;">
                                Houston, TX, USA | <a href="mailto:testifylearning.help@gmail.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`
};



       await sendEmailWithResend(mailOptions);
        res.status(200).json({ message: 'Password reset link sent to your email.' });

    } catch (error) {
        console.error("Forgot Password Error:", error);
        res.status(500).json({ message: 'Server error. Please try again later.' });
    }
});

// --- NEW ENDPOINT: Reset Password ---
app.post('/api/reset-password', async (req, res) => {
    const { email, token, newPassword } = req.body;
    
    if (!email || !token || !newPassword) {
        return res.status(400).json({ message: 'Missing required fields.' });
    }

    try {
        const emailLower = email.toLowerCase();
        const { Item } = await docClient.send(new GetCommand({ TableName: "TestifyUsers", Key: { email: emailLower } }));

        if (!Item || Item.resetToken !== token || Date.now() > Item.resetTokenExpiry) {
            return res.status(400).json({ message: 'Invalid or expired token.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        await docClient.send(new UpdateCommand({
            TableName: "TestifyUsers",
            Key: { email: emailLower },
            UpdateExpression: "set #pass = :newPassword remove resetToken, resetTokenExpiry",
            ExpressionAttributeNames: { "#pass": "password" },
            ExpressionAttributeValues: { ":newPassword": hashedPassword }
        }));
        
        res.status(200).json({ message: 'Password reset successfully. You can now log in with your new password.' });

    } catch (error) {
        console.error("Reset Password Error:", error);
        res.status(500).json({ message: 'Server error during password reset.' });
    }
});
// --- NEW ENDPOINT: Reset Password ---
app.post('/api/reset-password', async (req, res) => {
    const { email, token, newPassword } = req.body;
    
    if (!email || !token || !newPassword) {
        return res.status(400).json({ message: 'Missing required fields.' });
    }

    try {
        const emailLower = email.toLowerCase();
        const { Item } = await docClient.send(new GetCommand({ TableName: "TestifyUsers", Key: { email: emailLower } }));

        if (!Item || Item.resetToken !== token || Date.now() > Item.resetTokenExpiry) {
            return res.status(400).json({ message: 'Invalid or expired token.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        await docClient.send(new UpdateCommand({
            TableName: "TestifyUsers",
            Key: { email: emailLower },
            UpdateExpression: "set #pass = :newPassword remove resetToken, resetTokenExpiry",
            ExpressionAttributeNames: { "#pass": "password" },
            ExpressionAttributeValues: { ":newPassword": hashedPassword }
        }));
        
        res.status(200).json({ message: 'Password reset successfully. You can now log in with your new password.' });

    } catch (error) {
        console.error("Reset Password Error:", error);
        res.status(500).json({ message: 'Server error during password reset.' });
    }
});


////////////////////////////////////////Compiler End Points

app.post('/api/compiler/save-score', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') {
        return res.status(403).json({ message: 'Only students can save compiler scores.' });
    }
    
    // Destructure the new fields from the request body
    const { problemId, problemTitle, difficulty, score, submittedCode, language } = req.body;
    const studentEmail = req.user.email;

    // Add validation for the new fields
    if (!problemId || !problemTitle || !difficulty || score === undefined || !submittedCode || !language) {
        return res.status(400).json({ message: 'Missing required score data, code, or language.' });
    }
    
    try {
        // Check if a submission already exists for this user and problem
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyCompilerScores",
            FilterExpression: "studentEmail = :email AND problemId = :pid",
            ExpressionAttributeValues: {
                ":email": studentEmail,
                ":pid": problemId
            }
        }));

        // If a submission exists, UPDATE it with the new code and score
        if (Items && Items.length > 0) {
            const existingScoreId = Items[0].scoreId;
             await docClient.send(new UpdateCommand({
                TableName: "TestifyCompilerScores",
                Key: { scoreId: existingScoreId },
                UpdateExpression: "set #score = :s, #submittedCode = :c, #submittedAt = :t, #lang = :l",
                ExpressionAttributeNames: {
                    "#score": "score",
                    "#submittedCode": "submittedCode",
                    "#submittedAt": "submittedAt",
                    "#lang": "language"
                },
                ExpressionAttributeValues: {
                    ":s": score,
                    ":c": submittedCode,
                    ":t": new Date().toISOString(),
                    ":l": language
                }
            }));
            return res.status(200).json({ message: 'Submission updated successfully!' });
        } 
        // If it's a new submission, CREATE it
        else {
            const scoreId = uuidv4();
            const newScore = {
                scoreId,
                studentEmail,
                problemId,
                problemTitle,
                difficulty,
                score,
                submittedCode, // save the code
                language,      // save the language
                submittedAt: new Date().toISOString()
            };

            await docClient.send(new PutCommand({
                TableName: "TestifyCompilerScores",
                Item: newScore
            }));

            return res.status(201).json({ message: 'Score and code saved successfully!' });
        }

    } catch (error) {
        console.error("Save Compiler Score Error:", error);
        res.status(500).json({ message: 'Server error saving score.' });
    }
});


// GET endpoint for admins/moderators to view all compiler scores
app.get('/api/admin/compiler-scores', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    try {
        const { Items: scores } = await docClient.send(new ScanCommand({
            TableName: "TestifyCompilerScores",
            // ADDED FILTER: Only get items that are actual compiler scores,
            // not SQL sections or problems that pollute this table.
            // We identify compiler scores by the absence of the 'recordType' attribute.
            FilterExpression: "attribute_not_exists(recordType)"
        }));

        if (!scores || scores.length === 0) {
            return res.json([]);
        }

        const studentEmails = [...new Set(scores.map(s => s.studentEmail))];
        
        const keys = studentEmails.map(email => ({ email }));
        
        const { Responses } = await docClient.send(new BatchGetCommand({
            RequestItems: { "TestifyUsers": { Keys: keys, ProjectionExpression: "email, fullName, college" } }
        }));
        
        const students = Responses.TestifyUsers || [];
        const studentMap = new Map(students.map(s => [s.email, { fullName: s.fullName, college: s.college }]));

        // We are removing 'submittedCode' from this main list view for performance.
        // It will be fetched on demand when the admin clicks "View Code".
        const enrichedScores = scores.map(score => {
            const { submittedCode, ...rest } = score; // Exclude submittedCode here
            const studentInfo = studentMap.get(score.studentEmail);
            return {
                ...rest,
                studentName: studentInfo ? studentInfo.fullName : 'Unknown',
                college: studentInfo ? studentInfo.college : 'Unknown'
            };
        });
        
        enrichedScores.sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt));

        res.json(enrichedScores);

    } catch (error) {
        console.error("Get Compiler Scores Error:", error);
        res.status(500).json({ message: 'Server error fetching compiler scores.' });
    }
});

app.get('/api/compiler/submitted-problems', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') {
        return res.status(403).json({ message: 'Only students can view their submitted problems.' });
    }

    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyCompilerScores",
            FilterExpression: "studentEmail = :email",
            ExpressionAttributeValues: { ":email": req.user.email },
            ProjectionExpression: "problemId" // Only get the problemId to be efficient
        }));

        const problemIds = Items.map(item => item.problemId);
        res.json(problemIds);

    } catch (error) {
        console.error("Get Submitted Problems Error:", error);
        res.status(500).json({ message: 'Server error fetching submitted problems.' });
    }
});

app.get('/api/compiler/my-score', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') {
        return res.status(403).json({ message: 'Only students have a compiler score.' });
    }

    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyCompilerScores",
            FilterExpression: "studentEmail = :email",
            ExpressionAttributeValues: { ":email": req.user.email },
            ProjectionExpression: "score" // Only fetch the score attribute for efficiency
        }));

        const totalScore = Items.reduce((sum, item) => sum + (item.score || 0), 0);

        res.json({ totalScore });

    } catch (error) {
        console.error("Get My Score Error:", error);
        res.status(500).json({ message: 'Server error fetching score.' });
    }
});



//////////////////////////Compiler scores
app.post('/api/compiler/save-score', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') {
        return res.status(403).json({ message: 'Only students can save compiler scores.' });
    }
    
    // Destructure the new fields from the request body
    const { problemId, problemTitle, difficulty, score, submittedCode, language } = req.body;
    const studentEmail = req.user.email;

    // Add validation for the new fields
    if (!problemId || !problemTitle || !difficulty || score === undefined || !submittedCode || !language) {
        return res.status(400).json({ message: 'Missing required score data, code, or language.' });
    }
    
    try {
        // Check if a submission already exists for this user and problem
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyCompilerScores",
            FilterExpression: "studentEmail = :email AND problemId = :pid",
            ExpressionAttributeValues: {
                ":email": studentEmail,
                ":pid": problemId
            }
        }));

        // If a submission exists, UPDATE it with the new code and score
        if (Items && Items.length > 0) {
            const existingScoreId = Items[0].scoreId;
             await docClient.send(new UpdateCommand({
                TableName: "TestifyCompilerScores",
                Key: { scoreId: existingScoreId },
                UpdateExpression: "set #score = :s, #submittedCode = :c, #submittedAt = :t, #lang = :l",
                ExpressionAttributeNames: {
                    "#score": "score",
                    "#submittedCode": "submittedCode",
                    "#submittedAt": "submittedAt",
                    "#lang": "language"
                },
                ExpressionAttributeValues: {
                    ":s": score,
                    ":c": submittedCode,
                    ":t": new Date().toISOString(),
                    ":l": language
                }
            }));
            return res.status(200).json({ message: 'Submission updated successfully!' });
        } 
        // If it's a new submission, CREATE it
        else {
            const scoreId = uuidv4();
            const newScore = {
                scoreId,
                studentEmail,
                problemId,
                problemTitle,
                difficulty,
                score,
                submittedCode, // save the code
                language,      // save the language
                submittedAt: new Date().toISOString()
            };

            await docClient.send(new PutCommand({
                TableName: "TestifyCompilerScores",
                Item: newScore
            }));

            return res.status(201).json({ message: 'Score and code saved successfully!' });
        }

    } catch (error) {
        console.error("Save Compiler Score Error:", error);
        res.status(500).json({ message: 'Server error saving score.' });
    }
});

/**
 * NEW: Endpoint for an admin or moderator to get a single submission's details, including the code.
 * This is used in the admin panel to view a student's code.
 */
app.get('/api/compiler/submission/:scoreId', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    const { scoreId } = req.params;

    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: "TestifyCompilerScores",
            Key: { scoreId }
        }));

        if (!Item) {
            return res.status(404).json({ message: 'Submission not found.' });
        }

        // Return all details for the admin/moderator
        res.json(Item);

    } catch (error) {
        console.error("Get Submission Details Error:", error);
        res.status(500).json({ message: 'Server error fetching submission details.' });
    }
});

/**
 * NEW: Endpoint for a student to get their own submission for a specific problem.
 * This is used to load their previously submitted code back into the compiler editor.
 */
app.get('/api/compiler/my-submission/:problemId', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') {
        return res.status(403).json({ message: 'Access denied.' });
    }

    const { problemId } = req.params;
    const studentEmail = req.user.email;

    try {
         const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyCompilerScores",
            FilterExpression: "studentEmail = :email AND problemId = :pid",
            ExpressionAttributeValues: {
                ":email": studentEmail,
                ":pid": problemId
            }
        }));
        
        if (Items && Items.length > 0) {
            // A student should only have one submission record per problem, so we return the first one found.
            res.json(Items[0]);
        } else {
            res.status(404).json({ message: 'No submission found for this problem.' });
        }
    } catch (error) {
        console.error("Get My Submission Error:", error);
        res.status(500).json({ message: 'Server error fetching your submission.' });
    }
});

// =================================================================
// --- COMPLETE & REFACTORED COMPILER APIS (SINGLE TABLE DESIGN) ---
// =================================================================
// This is the complete set of backend endpoints for the dynamic compiler.
// It uses the new "TestifyCodeLab" table to keep data separate.
// =================================================================
// --- NEW: AI-POWERED PROBLEM GENERATION (ADMIN ONLY) ---
// =================================================================
// Add this endpoint to your backend.js file.

const adminOnlyAuth = (req, res, next) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied. Administrator privileges required.' });
    }
    next();
};


const TABLE_NAME = "TestifyCodeLab"; // Using a constant for the new table name

app.post('/api/admin/generate-problem-from-pdf', authMiddleware, adminOnlyAuth, async (req, res) => {
    const { text } = req.body;
    if (!text) {
        return res.status(400).json({ message: 'No text provided to generate problem.' });
    }

    try {
        const prompt = `Based on the following text from a coding problem document, create a structured JSON object representing the problem. The JSON must adhere strictly to the provided schema. Analyze the text to fill in all fields as accurately as possible. The 'example' field should contain both the input and output. The 'testCases' array must contain at least two distinct test cases extracted or inferred from the text.

Here is the text:\n\n${text}`;

        const schema = {
            type: "OBJECT",
            properties: {
                "title": { "type": "STRING", "description": "A concise title for the problem." },
                "description": { "type": "STRING", "description": "A detailed description of the problem statement." },
                "difficulty": { "type": "STRING", "enum": ["Easy", "Medium", "Hard", "CTS Specific"] },
                "inputFormat": { "type": "STRING", "description": "Description of the input format." },
                "outputFormat": { "type": "STRING", "description": "Description of the output format." },
                "constraints": { "type": "STRING", "description": "A list of constraints, each on a new line." },
                "example": { "type": "STRING", "description": "A formatted example showing sample input and output." },
                "testCases": {
                    "type": "ARRAY",
                    "description": "An array of at least two test cases.",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "input": { "type": "STRING", "description": "The input for the test case." },
                            "expected": { "type": "STRING", "description": "The expected output for the test case." }
                        },
                        "required": ["input", "expected"]
                    }
                }
            },
            required: ["title", "description", "difficulty", "testCases"]
        };

        const apiKey = process.env.GEMINI_API_KEY || 'AIzaSyAR_X4MZ75vxwV7OTU3dabFRcVe4SxWpb8';
        if (apiKey === 'YOUR_GEMINI_API_KEY') {
             return res.status(500).json({ message: 'Gemini API key is not configured on the server.' });
        }
        const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key=${apiKey}`;
        
        const payload = {
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: {
                responseMimeType: "application/json",
                responseSchema: schema
            }
        };

        const apiResponse = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!apiResponse.ok) {
            const errorBody = await apiResponse.text();
            console.error("Gemini API Error:", errorBody);
            throw new Error(`AI API call failed with status: ${apiResponse.status}`);
        }

        const result = await apiResponse.json();
        const jsonText = result.candidates[0].content.parts[0].text;
        const structuredProblem = JSON.parse(jsonText);

        res.json(structuredProblem);

    } catch (error) {
        console.error('Error in AI problem generation backend:', error);
        res.status(500).json({ message: 'Failed to generate problem using AI.' });
    }
});



// --- SECTION MANAGEMENT (ADMIN ONLY) ---

app.post('/api/compiler/sections', authMiddleware, adminOnlyAuth, async (req, res) => {
    const { sectionName, assignedColleges } = req.body;
    if (!sectionName) return res.status(400).json({ message: 'Section name is required.' });
    
    const sectionId = `section_${uuidv4()}`;
    const newSection = { 
        id: sectionId, 
        recordType: 'SECTION',
        sectionName, 
        assignedColleges: assignedColleges || [], 
        createdAt: new Date().toISOString() 
    };
    
    try {
        await docClient.send(new PutCommand({ TableName: TABLE_NAME, Item: newSection }));
        res.status(201).json(newSection);
    } catch (error) {
        console.error("Create Section Error:", error);
        res.status(500).json({ message: 'Server error creating section.' });
    }
});

app.get('/api/compiler/sections', authMiddleware, adminOnlyAuth, async (req, res) => {
    try {
        const { Items } = await docClient.send(new ScanCommand({ 
            TableName: TABLE_NAME,
            FilterExpression: "recordType = :type",
            ExpressionAttributeValues: { ":type": "SECTION" }
        }));
        Items.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        res.json(Items.map(item => ({...item, sectionId: item.id})));
    } catch (error) {
        console.error("Get Sections Error:", error);
        res.status(500).json({ message: 'Server error fetching sections.' });
    }
});

app.put('/api/compiler/sections/:id', authMiddleware, adminOnlyAuth, async (req, res) => {
    const { id } = req.params;
    const { sectionName, assignedColleges } = req.body;
    try {
        await docClient.send(new UpdateCommand({
            TableName: TABLE_NAME,
            Key: { id },
            UpdateExpression: "set sectionName = :name, assignedColleges = :colleges",
            ExpressionAttributeValues: { ":name": sectionName, ":colleges": assignedColleges || [] }
        }));
        res.status(200).json({ message: 'Section updated successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error updating section.' });
    }
});

app.delete('/api/compiler/sections/:id', authMiddleware, adminOnlyAuth, async (req, res) => {
    const { id } = req.params;
    try {
        await docClient.send(new DeleteCommand({ TableName: TABLE_NAME, Key: { id } }));
        res.status(200).json({ message: 'Section deleted successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error deleting section.' });
    }
});


// --- PROBLEM MANAGEMENT (ADMIN ONLY) ---

app.post('/api/compiler/problems', authMiddleware, adminOnlyAuth, async (req, res) => {
    const { sectionId, title, description, difficulty, inputFormat, outputFormat, constraints, example, testCases } = req.body;
    if (!sectionId || !title || !description || !difficulty || !testCases || testCases.length === 0) {
        return res.status(400).json({ message: 'Required fields are missing.' });
    }
    const problemId = `problem_${uuidv4()}`;
    const newProblem = { 
        id: problemId,
        recordType: 'PROBLEM',
        sectionId, title, description, difficulty, inputFormat, outputFormat, constraints, example, testCases, 
        createdAt: new Date().toISOString() 
    };

    try {
        await docClient.send(new PutCommand({ TableName: TABLE_NAME, Item: newProblem }));
        res.status(201).json(newProblem);
    } catch (error) {
        console.error("Create Problem Error:", error);
        res.status(500).json({ message: 'Server error creating problem.' });
    }
});

app.get('/api/compiler/problems', authMiddleware, adminOnlyAuth, async (req, res) => {
    try {
        const { Items } = await docClient.send(new ScanCommand({ 
            TableName: TABLE_NAME,
            FilterExpression: "recordType = :type",
            ExpressionAttributeValues: { ":type": "PROBLEM" }
        }));
        Items.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        res.json(Items.map(item => ({...item, problemId: item.id})));
    } catch (error) {
        console.error("Get Problems Error:", error);
        res.status(500).json({ message: 'Server error fetching problems.' });
    }
});

app.put('/api/compiler/problems/:id', authMiddleware, adminOnlyAuth, async (req, res) => {
    const { id } = req.params;
    // Destructure all problem fields from the request body, including the new 'score'
    const { sectionId, title, description, difficulty, score, inputFormat, outputFormat, constraints, example, testCases } = req.body;
    
    try {
        // Use the UpdateCommand to modify the item in DynamoDB
        await docClient.send(new UpdateCommand({
            TableName: TABLE_NAME,
            Key: { id },
            // UpdateExpression includes all fields that can be changed. We've added 'score = :s'.
            UpdateExpression: "set sectionId = :sid, title = :t, description = :d, difficulty = :diff, score = :s, inputFormat = :if, outputFormat = :of, #c = :cVal, example = :e, testCases = :tc",
            // ExpressionAttributeNames is used for attributes that are reserved keywords, like 'constraints'.
            ExpressionAttributeNames: {
                "#c": "constraints"
            },
            // ExpressionAttributeValues maps the placeholders in the UpdateExpression to the actual values.
            ExpressionAttributeValues: { 
                ":sid": sectionId, 
                ":t": title, 
                ":d": description, 
                ":diff": difficulty,
                ":s": score, // Added the score value here
                ":if": inputFormat, 
                ":of": outputFormat, 
                ":cVal": constraints,
                ":e": example, 
                ":tc": testCases 
            }
        }));
        // Send a success response
        res.status(200).json({ message: 'Problem updated successfully.' });
    } catch (error) {
        // Log any errors and send a server error response
        console.error("Update Problem Error:", error);
        res.status(500).json({ message: 'Server error updating problem.' });
    }
});



app.delete('/api/compiler/problems/:id', authMiddleware, adminOnlyAuth, async (req, res) => {
     const { id } = req.params;
    try {
        await docClient.send(new DeleteCommand({ TableName: TABLE_NAME, Key: { id } }));
        res.status(200).json({ message: 'Problem deleted successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error deleting problem.' });
    }
});


// --- STUDENT-FACING API TO GET ASSIGNED PROBLEMS ---

app.get('/api/student/compiler/problems', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Only students can access this resource.' });
    const studentCollege = req.user.college;
    if (!studentCollege) return res.json([]);

    try {
        const { Items } = await docClient.send(new ScanCommand({ TableName: TABLE_NAME }));

        const allSections = Items.filter(item => item.recordType === 'SECTION');
        const allProblems = Items.filter(item => item.recordType === 'PROBLEM');

        const allowedSections = allSections.filter(s => !s.assignedColleges || s.assignedColleges.length === 0 || s.assignedColleges.includes(studentCollege));
        const allowedSectionIds = new Set(allowedSections.map(s => s.id));
        const sectionMap = new Map(allSections.map(s => [s.id, s.sectionName]));

        const studentProblems = allProblems
            .filter(p => allowedSectionIds.has(p.sectionId))
            .map(p => ({ ...p, problemId: p.id, sectionName: sectionMap.get(p.sectionId) || 'Uncategorized' }));
            
        studentProblems.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        res.json(studentProblems);

    } catch (error) {
        console.error("Get Student Problems Error:", error);
        res.status(500).json({ message: 'Server error fetching problems.' });
    }
});


// --- SCORE & SUBMISSION APIS (SINGLE TABLE DESIGN) ---

app.post('/api/compiler/save-score', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Only students can save scores.' });
    
    const { problemId, problemTitle, difficulty, score, submittedCode, language } = req.body;
    const studentEmail = req.user.email;
    if (!problemId || !problemTitle || score === undefined || !submittedCode || !language) {
        return res.status(400).json({ message: 'Missing required score data.' });
    }
    
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: TABLE_NAME,
            FilterExpression: "recordType = :type AND studentEmail = :email AND problemId = :pid",
            ExpressionAttributeValues: { ":type": "SCORE", ":email": studentEmail, ":pid": problemId }
        }));

        if (Items && Items.length > 0) {
            const existingId = Items[0].id;
             await docClient.send(new UpdateCommand({
                TableName: TABLE_NAME,
                Key: { id: existingId },
                UpdateExpression: "set #score = :s, submittedCode = :c, submittedAt = :t, #lang = :l",
                ExpressionAttributeNames: { "#score": "score", "#lang": "language" },
                ExpressionAttributeValues: { ":s": score, ":c": submittedCode, ":t": new Date().toISOString(), ":l": language }
            }));
            return res.status(200).json({ message: 'Submission updated successfully!' });
        } else {
            const scoreId = `score_${uuidv4()}`;
            const newScore = {
                id: scoreId,
                recordType: 'SCORE',
                problemId, problemTitle, difficulty, score, submittedCode, language, studentEmail,
                submittedAt: new Date().toISOString()
            };
            await docClient.send(new PutCommand({ TableName: TABLE_NAME, Item: newScore }));
            return res.status(201).json({ message: 'Score and code saved successfully!' });
        }
    } catch (error) {
        console.error("Save Compiler Score Error:", error);
        res.status(500).json({ message: 'Server error saving score.' });
    }
});

app.get('/api/admin/compiler-scores', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin' && req.user.role !== 'Moderator') {
         return res.status(403).json({ message: 'Access denied.' });
    }
    try {
        const { Items: scores } = await docClient.send(new ScanCommand({
            TableName: TABLE_NAME,
            FilterExpression: "recordType = :type",
            ExpressionAttributeValues: { ":type": "SCORE" }
        }));
        
        if (!scores || scores.length === 0) return res.json([]);

        const studentEmails = [...new Set(scores.map(s => s.studentEmail))];
        const keys = studentEmails.map(email => ({ email }));
        
        const { Responses } = await docClient.send(new BatchGetCommand({
            RequestItems: { "TestifyUsers": { Keys: keys, ProjectionExpression: "email, fullName, college" } }
        }));
        
        const students = Responses.TestifyUsers || [];
        const studentMap = new Map(students.map(s => [s.email, { fullName: s.fullName, college: s.college }]));

        const enrichedScores = scores.map(score => {
            const studentInfo = studentMap.get(score.studentEmail);
            return {
                ...score,
                scoreId: score.id,
                studentName: studentInfo ? studentInfo.fullName : 'Unknown',
                college: studentInfo ? studentInfo.college : 'Unknown'
            };
        });
        
        enrichedScores.sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt));
        res.json(enrichedScores);

    } catch (error) {
        console.error("Get All Scores Error:", error);
        res.status(500).json({ message: 'Server error fetching scores.' });
    }
});

app.get('/api/compiler/submission/:scoreId', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin' && req.user.role !== 'Moderator') {
         return res.status(403).json({ message: 'Access denied.' });
    }
    const { scoreId } = req.params;
    try {
        const { Item } = await docClient.send(new GetCommand({ TableName: TABLE_NAME, Key: { id: scoreId } }));
        if (!Item || Item.recordType !== 'SCORE') {
            return res.status(404).json({ message: 'Submission not found.' });
        }
        res.json(Item);
    } catch (error) {
        console.error("Get Submission Details Error:", error);
        res.status(500).json({ message: 'Server error fetching submission details.' });
    }
});


app.get('/api/compiler/my-score', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: TABLE_NAME,
            FilterExpression: "recordType = :type AND studentEmail = :email",
            ExpressionAttributeValues: { ":type": "SCORE", ":email": req.user.email }
        }));
        const totalScore = Items.reduce((sum, item) => sum + (item.score || 0), 0);
        res.json({ totalScore });
    } catch (error) {
        console.error("Get My Score Error:", error);
        res.status(500).json({ message: 'Server error fetching score.' });
    }
});

app.get('/api/compiler/submitted-problems', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: TABLE_NAME,
            FilterExpression: "recordType = :type AND studentEmail = :email",
            ExpressionAttributeValues: { ":type": "SCORE", ":email": req.user.email }
        }));
        res.json(Items.map(item => item.problemId));
    } catch (error) {
        console.error("Get Submitted Problems Error:", error);
        res.status(500).json({ message: 'Server error fetching submitted problems.' });
    }
});

app.get('/api/compiler/my-submission/:problemId', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    const { problemId } = req.params;
    try {
         const { Items } = await docClient.send(new ScanCommand({
            TableName: TABLE_NAME,
            FilterExpression: "recordType = :type AND studentEmail = :email AND problemId = :pid",
            ExpressionAttributeValues: { ":type": "SCORE", ":email": req.user.email, ":pid": problemId }
        }));
        if (Items && Items.length > 0) {
            res.json(Items[0]);
        } else {
            res.status(404).json({ message: 'No submission found for this problem.' });
        }
    } catch (error) {
        console.error("Get My Submission Error:", error);
        res.status(500).json({ message: 'Server error fetching your submission.' });
    }
});


// =================================================================
// --- SQL CODELAB ENDPOINTS (REFACTORED TO USE ONECOMPILER API) ---
// =================================================================
// Using the "TestifyCompilerScores" table as requested for testing purposes.
const SQL_TABLE_NAME = "TestifyCompilerScores";

// Helper function to run SQL queries using the OneCompiler API.
// This replaces the local sqlite3 implementation.
const runQueryWithOneCompiler = async (schema, query) => {
    // It's recommended to store this API key in environment variables for security.
    const ONECOMPILER_API_KEY = process.env.ONECOMPILER_API_KEY || '09ccf0b69bmsh066f3a3bc867b99p178664jsna5e9720da3f6';

    // Combine schema (CREATE, INSERT statements) and the user's query into a single script.
    const fullScript = `${schema || ''}\n\n${query || ''}`;

    const payload = {
        language: "mysql", // OneCompiler uses 'mysql' for standard SQL execution
        stdin: "",
        files: [{
            name: "script.sql",
            content: fullScript
        }]
    };

    try {
        const response = await fetch('https://onecompiler-apis.p.rapidapi.com/api/v1/run', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-RapidAPI-Key': '22be928fe3msh1ad95638f83d75cp18c454jsn9883d64a5a33',
                'X-RapidAPI-Host': 'onecompiler-apis.p.rapidapi.com'
            },
            body: JSON.stringify(payload)
        });

        const result = await response.json();

        // Check for compilation or runtime errors from the API response
        if (!response.ok || result.stderr || result.exception) {
            throw new Error(result.stderr || result.exception || result.message || 'An error occurred during SQL execution.');
        }

        // Parse the raw stdout from OneCompiler into the { columns, values } format
        const output = (result.stdout || '').trim();
        if (!output) {
            // Query ran successfully but produced no rows
            return { columns: [], values: [] };
        }

        const lines = output.split('\n');
        const headerLine = lines.shift();
        if (!headerLine) {
            return { columns: [], values: [] };
        }
        
        // OneCompiler's SQL output is typically tab-separated
        const columns = headerLine.split('\t');
        
        const values = lines.map(line => {
            const rowValues = line.split('\t');
            const rowObject = {};
            columns.forEach((col, index) => {
                rowObject[col] = rowValues[index] !== undefined ? rowValues[index] : null;
            });
            return rowObject;
        });

        return { columns, values };

    } catch (error) {
        console.error("OneCompiler SQL Execution Error:", error.message);
        // Re-throw the error so it's sent to the client
        throw error;
    }
};


// --- SQL SECTION MANAGEMENT (ADMIN ONLY) ---

app.post('/api/sql/sections', authMiddleware, adminOnlyAuth, async (req, res) => {
    const { sectionName, assignedColleges } = req.body;
    const scoreId = `section_${uuidv4()}`;
    const newSection = {
        scoreId,
        recordType: 'SECTION',
        sectionName,
        assignedColleges: assignedColleges || [],
        createdAt: new Date().toISOString()
    };
    try {
        await docClient.send(new PutCommand({ TableName: SQL_TABLE_NAME, Item: newSection }));
        res.status(201).json(newSection);
    } catch (error) {
        console.error("Create SQL Section Error:", error);
        res.status(500).json({ message: 'Server error creating section.' });
    }
});

app.get('/api/sql/sections', authMiddleware, adminOnlyAuth, async (req, res) => {
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: SQL_TABLE_NAME,
            FilterExpression: "recordType = :type",
            ExpressionAttributeValues: { ":type": "SECTION" }
        }));
        res.json(Items.map(item => ({...item, id: item.scoreId})));
    } catch (error) {
        console.error("Get SQL Sections Error:", error);
        res.status(500).json({ message: 'Server error fetching sections.' });
    }
});

app.put('/api/sql/sections/:id', authMiddleware, adminOnlyAuth, async (req, res) => {
    const { id } = req.params;
    const { sectionName, assignedColleges } = req.body;
    try {
        await docClient.send(new UpdateCommand({
            TableName: SQL_TABLE_NAME,
            Key: { scoreId: id },
            UpdateExpression: "set sectionName = :name, assignedColleges = :colleges",
            ExpressionAttributeValues: { ":name": sectionName, ":colleges": assignedColleges || [] }
        }));
        res.status(200).json({ message: 'Section updated.' });
    } catch (error) {
        console.error("Update SQL Section Error:", error);
        res.status(500).json({ message: 'Server error updating section.' });
    }
});

app.delete('/api/sql/sections/:id', authMiddleware, adminOnlyAuth, async (req, res) => {
    const { id } = req.params;
    try {
        await docClient.send(new DeleteCommand({ TableName: SQL_TABLE_NAME, Key: { scoreId: id } }));
        res.status(200).json({ message: 'Section deleted.' });
    } catch (error) {
        console.error("Delete SQL Section Error:", error);
        res.status(500).json({ message: 'Server error deleting section.' });
    }
});

// --- SQL PROBLEM MANAGEMENT (ADMIN ONLY) ---

app.post('/api/sql/problems', authMiddleware, adminOnlyAuth, async (req, res) => {
    const { sectionId, title, description, difficulty, schema, constraints, correctQuery } = req.body;
    const scoreId = `problem_${uuidv4()}`;
    const newProblem = {
        scoreId, recordType: 'PROBLEM', sectionId, title, description, difficulty, schema, constraints, correctQuery,
        createdAt: new Date().toISOString()
    };
    try {
        await docClient.send(new PutCommand({ TableName: SQL_TABLE_NAME, Item: newProblem }));
        res.status(201).json(newProblem);
    } catch (error) {
        console.error("Create SQL Problem Error:", error);
        res.status(500).json({ message: 'Server error creating problem.' });
    }
});

app.get('/api/sql/problems', authMiddleware, adminOnlyAuth, async (req, res) => {
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: SQL_TABLE_NAME,
            FilterExpression: "recordType = :type",
            ExpressionAttributeValues: { ":type": "PROBLEM" }
        }));
        res.json(Items.map(item => ({...item, id: item.scoreId})));
    } catch (error) {
        console.error("Get SQL Problems Error:", error);
        res.status(500).json({ message: 'Server error fetching problems.' });
    }
});

app.put('/api/sql/problems/:id', authMiddleware, adminOnlyAuth, async (req, res) => {
    const { id } = req.params;
    const { sectionId, title, description, difficulty, schema, constraints, correctQuery } = req.body;
    try {
        await docClient.send(new UpdateCommand({
            TableName: SQL_TABLE_NAME,
            Key: { scoreId: id },
            UpdateExpression: "set sectionId = :sid, title = :t, description = :d, difficulty = :diff, #s = :schema, #c = :constraints, correctQuery = :cq",
            ExpressionAttributeNames: { "#s": "schema", "#c": "constraints" },
            ExpressionAttributeValues: { ":sid": sectionId, ":t": title, ":d": description, ":diff": difficulty, ":schema": schema, ":constraints": constraints, ":cq": correctQuery }
        }));
        res.status(200).json({ message: 'Problem updated.' });
    } catch (error) {
        console.error("Update SQL Problem Error:", error);
        res.status(500).json({ message: 'Server error updating problem.' });
    }
});

app.delete('/api/sql/problems/:id', authMiddleware, adminOnlyAuth, async (req, res) => {
     const { id } = req.params;
    try {
        await docClient.send(new DeleteCommand({ TableName: SQL_TABLE_NAME, Key: { scoreId: id } }));
        res.status(200).json({ message: 'Problem deleted.' });
    } catch (error) {
        console.error("Delete SQL Problem Error:", error);
        res.status(500).json({ message: 'Server error deleting problem.' });
    }
});

// --- STUDENT-FACING SQL API ---

app.get('/api/student/sql/problems', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    const studentCollege = req.user.college;
    
    try {
        const { Items } = await docClient.send(new ScanCommand({ TableName: SQL_TABLE_NAME }));
        const sections = Items.filter(i => i.recordType === 'SECTION');
        const problems = Items.filter(i => i.recordType === 'PROBLEM');

        const allowedSections = sections.filter(s => !s.assignedColleges || s.assignedColleges.length === 0 || s.assignedColleges.includes(studentCollege));
        const allowedSectionIds = new Set(allowedSections.map(s => s.scoreId));
        const sectionMap = new Map(sections.map(s => [s.scoreId, s.sectionName]));

        const studentProblems = problems
            .filter(p => allowedSectionIds.has(p.sectionId))
            .map(p => ({ ...p, problemId: p.scoreId, sectionName: sectionMap.get(p.sectionId) || 'Uncategorized' }));
            
        res.json(studentProblems);
    } catch (error) {
        console.error("Get Student SQL Problems Error:", error);
        res.status(500).json({ message: 'Server error fetching problems.' });
    }
});

// --- SQL EXECUTION AND SCORING APIS ---

// MODIFIED: This endpoint now uses the OneCompiler API instead of local sqlite.
app.post('/api/sql/run', authMiddleware, async (req, res) => {
    const { schema, query } = req.body;
    try {
        const result = await runQueryWithOneCompiler(schema, query);
        res.json(result);
    } catch (error) {
        res.status(400).json({ message: error.message, error: error.message });
    }
});

// MODIFIED: This endpoint now uses the OneCompiler API for validation.
app.post('/api/sql/save-score', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') {
        return res.status(403).json({ message: 'Only students can submit solutions.' });
    }

    const { problemId, submittedCode } = req.body;
    const studentEmail = req.user.email;

    if (!problemId || !submittedCode) {
        return res.status(400).json({ message: 'Problem ID and submitted code are required.' });
    }

    try {
        const { Item: problem } = await docClient.send(new GetCommand({
            TableName: SQL_TABLE_NAME,
            Key: { scoreId: problemId }
        }));
        
        if (!problem || problem.recordType !== 'PROBLEM') {
            return res.status(404).json({ message: 'Problem not found.' });
        }

        let studentResult, correctResult, isCorrect = false;

        try {
            // Run both the student's query and the correct query via the API
            [studentResult, correctResult] = await Promise.all([
                runQueryWithOneCompiler(problem.schema, submittedCode),
                runQueryWithOneCompiler(problem.schema, problem.correctQuery)
            ]);
            
            // Helper to create a consistent, sorted string from a row for comparison
            const canonicalRow = (row, columns) => {
                return columns.map(col => `${col}:${row[col]}`).sort().join('|');
            };
            
            // Sort the values arrays of both results to ensure order doesn't affect comparison
            if (studentResult.values && studentResult.columns) {
                studentResult.values.sort((a, b) => canonicalRow(a, studentResult.columns).localeCompare(canonicalRow(b, studentResult.columns)));
            }
            if (correctResult.values && correctResult.columns) {
                correctResult.values.sort((a, b) => canonicalRow(a, correctResult.columns).localeCompare(canonicalRow(b, correctResult.columns)));
            }
            
            // Compare the canonicalized results
            isCorrect = JSON.stringify(studentResult) === JSON.stringify(correctResult);

        } catch (error) {
            // This will catch execution errors from the API call
            studentResult = { error: error.message };
        }
        
        const scoreMap = { 'Easy': 10, 'Medium': 20, 'Hard': 30, 'CTS Specific': 25 };
        const score = isCorrect ? (scoreMap[problem.difficulty] || 10) : 0;

        const { Items } = await docClient.send(new ScanCommand({
            TableName: SQL_TABLE_NAME,
            FilterExpression: "studentEmail = :email AND problemId = :pid AND recordType = :type",
            ExpressionAttributeValues: { ":email": studentEmail, ":pid": problemId, ":type": "SCORE" }
        }));

        if (Items && Items.length > 0) {
            const existingScoreId = Items[0].scoreId;
            await docClient.send(new UpdateCommand({
                TableName: SQL_TABLE_NAME,
                Key: { scoreId: existingScoreId },
                UpdateExpression: "set #s = :score, #sc = :code, #sa = :time",
                ExpressionAttributeNames: { "#s": "score", "#sc": "submittedCode", "#sa": "submittedAt" },
                ExpressionAttributeValues: { ":score": score, ":code": submittedCode, ":time": new Date().toISOString() }
            }));
        } else {
            const newScoreId = `score_${uuidv4()}`;
            const newScoreRecord = {
                scoreId: newScoreId,
                recordType: 'SCORE',
                problemId, studentEmail,
                problemTitle: problem.title,
                difficulty: problem.difficulty,
                score, submittedCode,
                submittedAt: new Date().toISOString()
            };
            await docClient.send(new PutCommand({ TableName: SQL_TABLE_NAME, Item: newScoreRecord }));
        }

        res.status(200).json({
            isCorrect: isCorrect,
            message: isCorrect ? 'Correct!' : 'Incorrect.',
            score: score,
            result: studentResult
        });

    } catch (error) {
        console.error("SQL Submit Error:", error);
        res.status(500).json({ message: 'An error occurred on the server during submission.' });
    }
});


// --- ADMIN & STUDENT SCORE/SUBMISSION RETRIEVAL ---

app.get('/api/admin/sql-scores', authMiddleware, adminOnlyAuth, async (req, res) => {
    try {
        const { Items: scores } = await docClient.send(new ScanCommand({
            TableName: SQL_TABLE_NAME,
            FilterExpression: "recordType = :type",
            ExpressionAttributeValues: { ":type": "SCORE" }
        }));

        if (!scores || scores.length === 0) return res.json([]);

        const studentEmails = [...new Set(scores.map(s => s.studentEmail))];
        const keys = studentEmails.map(email => ({ email }));
        
        const { Responses } = await docClient.send(new BatchGetCommand({
            RequestItems: { "TestifyUsers": { Keys: keys, ProjectionExpression: "email, fullName, college" } }
        }));
        
        const students = Responses.TestifyUsers || [];
        const studentMap = new Map(students.map(s => [s.email, { fullName: s.fullName, college: s.college }]));

        const enrichedScores = scores.map(score => {
            const studentInfo = studentMap.get(score.studentEmail);
            return {
                ...score,
                id: score.scoreId, // For frontend compatibility
                studentName: studentInfo ? studentInfo.fullName : 'Unknown',
                college: studentInfo ? studentInfo.college : 'Unknown'
            };
        });

        res.json(enrichedScores);
    } catch (error) {
        console.error("Get Admin SQL Scores Error:", error);
        res.status(500).json({ message: 'Server error fetching scores.' });
    }
});

app.get('/api/sql/submission/:scoreId', authMiddleware, adminOnlyAuth, async (req, res) => {
    const { scoreId } = req.params;
    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: SQL_TABLE_NAME,
            Key: { scoreId: scoreId }
        }));

        if (!Item || Item.recordType !== 'SCORE') {
            return res.status(404).json({ message: 'Submission not found.' });
        }
        res.json(Item);
    } catch (error) {
        console.error("Get SQL Submission Error:", error);
        res.status(500).json({ message: 'Server error fetching submission.' });
    }
});

app.get('/api/sql/my-score', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: SQL_TABLE_NAME,
            FilterExpression: "recordType = :type AND studentEmail = :email",
            ExpressionAttributeValues: { ":type": "SCORE", ":email": req.user.email }
        }));
        const totalScore = Items.reduce((sum, item) => sum + (item.score || 0), 0);
        res.json({ totalScore });
    } catch (error) {
        console.error("Get My SQL Score Error:", error);
        res.status(500).json({ message: 'Server error fetching score.' });
    }
});

app.get('/api/sql/submitted-problems', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: SQL_TABLE_NAME,
            FilterExpression: "recordType = :type AND studentEmail = :email AND score > :zero",
            ExpressionAttributeValues: { 
                ":type": "SCORE", 
                ":email": req.user.email,
                ":zero": 0 
            }
        }));
        res.json(Items.map(item => item.problemId));
    } catch (error) {
        console.error("Get SQL Submitted Problems Error:", error);
        res.status(500).json({ message: 'Server error fetching submitted problems.' });
    }
});

app.get('/api/sql/my-submission/:problemId', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    const { problemId } = req.params;
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: SQL_TABLE_NAME,
            FilterExpression: "recordType = :type AND studentEmail = :email AND problemId = :pid",
            ExpressionAttributeValues: { ":type": "SCORE", ":email": req.user.email, ":pid": problemId }
        }));
        if (Items && Items.length > 0) {
            res.json(Items[0]);
        } else {
            res.status(404).json({ message: 'No submission found for this problem.' });
        }
    } catch (error) {
        console.error("Get My SQL Submission Error:", error);
        res.status(500).json({ message: 'Server error fetching submission.' });
    }
});

////////////////////////////////////////////
// --- REQUIRED IMPORTS (add these to your main backend.js) ---
// const { v4: uuidv4 } = require('uuid');
// const { DynamoDBDocumentClient, PutCommand, GetCommand, ScanCommand, UpdateCommand, DeleteCommand } = require("@aws-sdk/lib-dynamodb");

// --- TABLE NAME CONSTANT ---
// Per user request, using TestifyCompilerScores for all contest data.
const CONTEST_TABLE = "TestifyCompilerScores"; 

// =================================================================
// --- ADMIN: CODING CONTEST MANAGEMENT ENDPOINTS ---
// =================================================================

// POST a new coding contest
app.post('/api/admin/contests', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }

    const { title, startTime, duration, isProctored, problems, totalMarks, assignedColleges } = req.body;
    if (!title || !startTime || !duration || !problems || problems.length === 0) {
        return res.status(400).json({ message: 'Missing required contest fields.' });
    }

    const contestId = `contest_${uuidv4()}`;
    const newContest = {
        // FIXED: Changed 'id' to 'scoreId' to match the table's primary key.
        scoreId: contestId,
        recordType: 'CONTEST',
        title,
        startTime,
        duration,
        isProctored,
        problems, // Array of { problemId, title, difficulty, score }
        totalMarks,
        assignedColleges: assignedColleges || [],
        createdAt: new Date().toISOString()
    };

    try {
        await docClient.send(new PutCommand({ TableName: CONTEST_TABLE, Item: newContest }));
        
        // Send email notification to students in assigned colleges
        if (assignedColleges && assignedColleges.length > 0) {
            const filterExpression = assignedColleges.map((_, index) => `college = :c${index}`).join(' OR ');
            const expressionAttributeValues = {};
            assignedColleges.forEach((college, index) => {
                expressionAttributeValues[`:c${index}`] = college;
            });
            const { Items: students } = await docClient.send(new ScanCommand({
                TableName: "TestifyUsers",
                FilterExpression: filterExpression,
                // FIXED: Added the missing ExpressionAttributeValues parameter to the ScanCommand
                ExpressionAttributeValues: expressionAttributeValues,
                ProjectionExpression: "email"
            }));
            
           const studentEmails = students.map(s => s.email);
if (studentEmails.length > 0) {
    const mailOptions = {
        from: '"TESTIFY" <testifylearning.help@gmail.com>',
        to: studentEmails.join(','),
        subject: `New Coding Contest Assigned: ${title}`,
        html: `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>New Coding Contest</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap');
        body { font-family: 'Poppins', Arial, sans-serif; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }
        a { text-decoration: none; }
        @media screen and (max-width: 600px) {
            .content-width {
                width: 90% !important;
            }
        }
    </style>
</head>
<body style="background-color: #f3f4f6; margin: 0; padding: 0;">
    <!-- Preheader text for inbox preview -->
    <span style="display:none;font-size:1px;color:#ffffff;line-height:1px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;">
        A new coding contest is waiting for you!
    </span>
    <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #f3f4f6;">
        <tr>
            <td align="center" style="padding: 40px 20px;">
                <!-- Main Card -->
                <table class="content-width" width="600" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #ffffff; border-radius: 12px; box-shadow: 0 10px 30px -10px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td align="center" style="padding: 30px 40px 20px; border-bottom: 1px solid #e5e7eb;">
                            <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1756037774/Gemini_Generated_Image_eu0ib0eu0ib0eu0i_z0amjh.png" 
                                 alt="Testify Logo" style="height: 50px; width: auto;">
                        </td>
                    </tr>
                    
                    <!-- Content Body -->
                    <tr>
                        <td align="center" style="padding: 40px; text-align: center;">
                             <h1 style="font-family: 'Poppins', Arial, sans-serif; font-size: 26px; font-weight: 700; color: #111827; margin: 0 0 15px;">New Coding Contest!</h1>
                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 16px; color: #4b5563; margin: 0 0 30px; line-height: 1.7;">
                                 A new coding contest, "<b>${title}</b>", has been assigned to you. Sharpen your skills and compete with your peers!
                             </p>
                             <a href="https://testify-io-ai.onrender.com/student/contests.html" 
                                target="_blank"
                                style="display: inline-block; padding: 15px 35px; font-family: 'Poppins', Arial, sans-serif; font-size: 16px; font-weight: 600; color: #ffffff; background-color: #db2777; border-radius: 8px; text-decoration: none;">
                                 Go to Contest
                             </a>
                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 14px; color: #6b7280; margin: 30px 0 0;">
                                 Good luck!
                             </p>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td align="center" style="padding: 30px 40px; background-color: #f9fafb; border-top: 1px solid #e5e7eb; border-radius: 0 0 12px 12px;">
                            <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0 0 8px;">
                                &copy; ${new Date().getFullYear()} TESTIFY. All rights reserved.
                            </p>
                            <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0;">
                                Houston, TX, USA | <a href="mailto:testifylearning.help@gmail.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>`
    };
               await sendEmailWithResend(mailOptions);
            }
        }
        
        res.status(201).json({ message: 'Contest created successfully!', contest: newContest });

    } catch (error) {
        console.error("Create Contest Error:", error);
        res.status(500).json({ message: 'Server error creating contest.' });
    }
});

// GET all coding contests (for Admin view)
app.get('/api/admin/contests', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: CONTEST_TABLE,
            FilterExpression: "recordType = :type",
            ExpressionAttributeValues: { ":type": "CONTEST" }
        }));
        Items.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        // MODIFIED: Map scoreId to id for frontend compatibility
        res.json(Items.map(item => ({ ...item, id: item.scoreId })));
    } catch (error) {
        console.error("Get Contests Error:", error);
        res.status(500).json({ message: 'Server error fetching contests.' });
    }
});

// NEW: DELETE a contest
app.delete('/api/admin/contests/:id', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    try {
        // FIXED: Use 'scoreId' as the key for deletion.
        await docClient.send(new DeleteCommand({ 
            TableName: CONTEST_TABLE, 
            Key: { scoreId: req.params.id } 
        }));
        res.status(200).json({ message: 'Contest deleted successfully.' });
    } catch (error) {
        console.error("Delete Contest Error:", error);
        res.status(500).json({ message: 'Server error deleting contest.' });
    }
});

// NEW: GET all submissions for a specific contest
app.get('/api/admin/contests/:id/submissions', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: CONTEST_TABLE,
            FilterExpression: "recordType = :type AND contestId = :cid",
            ExpressionAttributeValues: { 
                ":type": "CONTEST_SUBMISSION",
                ":cid": req.params.id
            }
        }));
        Items.sort((a, b) => b.totalScore - a.totalScore); // Sort by score descending
        res.json(Items);
    } catch (error) {
        console.error("Get Contest Submissions Error:", error);
        res.status(500).json({ message: 'Server error fetching submissions.' });
    }
});


// =================================================================
// --- STUDENT: CODING CONTEST ENDPOINTS ---
// =================================================================
// const CONTEST_TABLE = "TestifyCompilerScores";

// [No Change Needed] ADMIN: GET all contests (for the management list)
app.post('/api/admin/contests', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }

    const { title, startTime, duration, isProctored, problems, totalMarks, assignedColleges } = req.body;
    if (!title || !startTime || !duration || !problems || problems.length === 0) {
        return res.status(400).json({ message: 'Missing required contest fields.' });
    }

    const contestId = `contest_${uuidv4()}`;
    const newContest = {
        scoreId: contestId, // Primary Key for TestifyCompilerScores table
        recordType: 'CONTEST',
        id: contestId, // Keep a consistent 'id' field for frontend simplicity
        title,
        startTime,
        duration,
        isProctored,
        problems, // This now contains the full problem objects
        totalMarks,
        assignedColleges: assignedColleges || [],
        createdAt: new Date().toISOString()
    };

    try {
        await docClient.send(new PutCommand({ TableName: "TestifyCompilerScores", Item: newContest }));

        // Send email notification if colleges are assigned
        if (assignedColleges && assignedColleges.length > 0) {
            const filterExpression = assignedColleges.map((_, index) => `college = :c${index}`).join(' OR ');
            const expressionAttributeValues = {};
            assignedColleges.forEach((college, index) => {
                expressionAttributeValues[`:c${index}`] = college;
            });

            const { Items: students } = await docClient.send(new ScanCommand({
                TableName: "TestifyUsers",
                FilterExpression: filterExpression,
                ExpressionAttributeValues: expressionAttributeValues,
                ProjectionExpression: "email"
            }));

            const studentEmails = students.map(s => s.email);
            if (studentEmails.length > 0) {
                const mailOptions = {
                    from: '"TESTIFY" <testifylearning.help@gmail.com>',
                    to: studentEmails.join(','),
                    subject: `New Coding Contest Assigned: ${title}`,
                    html: `<p>Hello,</p><p>A new coding contest, "<b>${title}</b>", has been assigned to you. Please log in to your TESTIFY dashboard to participate.</p><p>Best regards,<br/>The TESTIFY Team</p>`
                };
               await sendEmailWithResend(mailOptions);
            }
        }

        res.status(201).json({ message: 'Contest created and notifications sent successfully!', contest: newContest });

    } catch (error) {
        console.error("Create Contest Error:", error);
        res.status(500).json({ message: 'Server error creating contest.' });
    }
});

// [No Change Needed] ADMIN: Create a new contest
app.post('/api/admin/contests', authMiddleware, async (req, res) => {
    // This endpoint should now receive the full problem details from the updated create-contest.html
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    const { title, startTime, duration, isProctored, problems, totalMarks, assignedColleges } = req.body;
    if (!title || !startTime || !duration || !problems || problems.length === 0) {
        return res.status(400).json({ message: 'Missing required contest fields.' });
    }
    const contestId = `contest_${uuidv4()}`;
    const newContest = {
        scoreId: contestId,
        recordType: 'CONTEST',
        title, startTime, duration, isProctored, problems, totalMarks,
        assignedColleges: assignedColleges || [],
        createdAt: new Date().toISOString()
    };
    try {
        await docClient.send(new PutCommand({ TableName: CONTEST_TABLE, Item: newContest }));
        res.status(201).json({ message: 'Contest created successfully!', contest: newContest });
    } catch (error) {
        console.error("Create Contest Error:", error);
        res.status(500).json({ message: 'Server error creating contest.' });
    }
});

// [No Change Needed] STUDENT: Get list of assigned contests
app.get('/api/student/contests', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    const studentCollege = req.user.college;
    if (!studentCollege) return res.json([]);
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: CONTEST_TABLE,
            FilterExpression: "recordType = :type AND (contains(assignedColleges, :college) OR size(assignedColleges) = :zero)",
            ExpressionAttributeValues: { ":type": "CONTEST", ":college": studentCollege, ":zero": 0 }
        }));
        res.json(Items.map(item => ({ ...item, id: item.scoreId })));
    } catch (error) {
        console.error("Get Student Contests Error:", error);
        res.status(500).json({ message: 'Server error fetching contests.' });
    }
});

// [CORRECTED] STUDENT: Get full details for a single contest
app.get('/api/student/contests/:id', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    try {
        const { Item: contest } = await docClient.send(new GetCommand({
            TableName: CONTEST_TABLE,
            Key: { scoreId: req.params.id }
        }));
        if (!contest || contest.recordType !== 'CONTEST') {
            return res.status(404).json({ message: 'Contest not found.' });
        }
        res.json({ ...contest, id: contest.scoreId });
    } catch (error) {
        console.error("Get Single Contest Error:", error);
        res.status(500).json({ message: 'Server error fetching contest details.' });
    }
});

// [NEW & SECURE] STUDENT: Submit contest for scoring
app.post('/api/student/contests/submit', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });

    const { contestId, submissions, violationReason } = req.body;
    const studentEmail = req.user.email;

    try {
        const { Item: contest } = await docClient.send(new GetCommand({
            TableName: "TestifyCompilerScores",
            Key: { scoreId: contestId }
        }));

        if (!contest || contest.recordType !== 'CONTEST') {
            return res.status(404).json({ message: "Contest not found." });
        }

        let totalScore = 0;
        const detailedSubmissions = [];

        // Loop through each submitted problem to evaluate it
        for (const sub of submissions) {
            const problem = contest.problems.find(p => p.id === sub.problemId);
            if (!problem || !problem.testCases || problem.testCases.length === 0) continue;

            let passedCases = 0;
            // Evaluate against each test case
            for (const tc of problem.testCases) {
                // IMPORTANT: This re-uses your existing /api/compile endpoint logic
                const compileResponse = await fetch('http://localhost:3000/api/compile', { // Ensure this URL is correct for your setup
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'x-auth-token': req.header('x-auth-token') },
                    body: JSON.stringify({ language: sub.language, code: sub.code, input: tc.input }),
                });

                if (compileResponse.ok) {
                    const compileResult = await compileResponse.json();
                    const actual = (compileResult.output || '').trim().replace(/\s+/g, ' ');
                    const expected = (tc.expected || '').trim().replace(/\s+/g, ' ');
                    if (actual === expected) {
                        passedCases++;
                    }
                }
            }

            // Calculate score for this specific problem
            const problemScore = Math.round((passedCases / problem.testCases.length) * problem.score);
            totalScore += problemScore;

            detailedSubmissions.push({
                ...sub, // Includes problemId, code, language
                problemTitle: problem.title,
                score: problemScore,
                passedCases: passedCases,
                totalCases: problem.testCases.length
            });
        }

        const submissionId = `contestsub_${uuidv4()}`;
        const newSubmission = {
            scoreId: submissionId,
            recordType: 'CONTEST_SUBMISSION',
            contestId,
            studentEmail,
            studentName: req.user.fullName,
            college: req.user.college,
            submissions: detailedSubmissions,
            totalScore,
            maxScore: contest.totalMarks,
            contestTitle: contest.title,
            violationReason: violationReason || null,
            submittedAt: new Date().toISOString()
        };

        await docClient.send(new PutCommand({ TableName: "TestifyCompilerScores", Item: newSubmission }));
        res.status(201).json({ message: 'Contest submitted successfully!' });

    } catch (error) {
        console.error("Submit Contest Error:", error);
        res.status(500).json({ message: 'Server error submitting contest.' });
    }
});


// [NEW] STUDENT: Get history of contest submissions
app.get('/api/student/contest-history', authMiddleware, async(req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: CONTEST_TABLE,
            FilterExpression: "recordType = :type AND studentEmail = :email",
            ExpressionAttributeValues: {
                ":type": "CONTEST_SUBMISSION",
                ":email": req.user.email
            }
        }));
        Items.sort((a,b) => new Date(b.submittedAt) - new Date(a.submittedAt));
        res.json(Items);
    } catch (error) {
        console.error("Get Contest History Error:", error);
        res.status(500).json({ message: 'Server error fetching history.' });
    }
});

// [NEW] STUDENT: Get the detailed result for a single submission
app.get('/api/student/contest-result/:id', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: CONTEST_TABLE,
            Key: { scoreId: req.params.id }
        }));
        if (!Item || Item.studentEmail !== req.user.email) {
            return res.status(404).json({ message: 'Result not found.' });
        }
        res.json(Item);
    } catch (error) {
        console.error("Get Contest Result Error:", error);
        res.status(500).json({ message: 'Server error fetching result.' });
    }
});

// ... existing backend code ...

app.get('/cognizant-cloud', authMiddleware, (req, res) => {
    // This route is now protected by your authMiddleware.
    // It will only execute if the user provides a valid token.
    res.sendFile(path.join(__dirname, 'protected_pages', 'cognizant-cloud.html'));
});

app.get('/api/admin/course-progress', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    try {
        const { Items: courses } = await docClient.send(new ScanCommand({ TableName: "TestifyCourses" }));
        const { Items: progressRecords } = await docClient.send(new ScanCommand({ TableName: "TestifyCourseProgress" }));

        let relevantProgress = progressRecords;

        if (req.user.role === 'Moderator') {
            const { assignedColleges } = req.user;
            if (!assignedColleges || assignedColleges.length === 0) return res.json([]);
            
            const studentEmailsInColleges = new Set();
            const filterExpression = assignedColleges.map((_, i) => `college = :c${i}`).join(' OR ');
            const expressionAttributeValues = assignedColleges.reduce((acc, val, i) => ({ ...acc, [`:c${i}`]: val }), {});
            
            const { Items: students } = await docClient.send(new ScanCommand({
                TableName: "TestifyUsers",
                FilterExpression: filterExpression,
                ExpressionAttributeValues: expressionAttributeValues,
                ProjectionExpression: "email"
            }));

            students.forEach(s => studentEmailsInColleges.add(s.email));
            relevantProgress = progressRecords.filter(p => studentEmailsInColleges.has(p.studentEmail));
        }

        const progressMap = new Map();
        relevantProgress.forEach(p => {
            if (!progressMap.has(p.courseId)) progressMap.set(p.courseId, []);
            progressMap.get(p.courseId).push(p);
        });

        const overview = courses.map(course => {
            const courseProgress = progressMap.get(course.courseId) || [];
            const totalSubModules = course.modules.reduce((acc, module) => acc + module.subModules.length, 0);
            
            let completedCount = 0;
            let inProgressCount = 0;

            courseProgress.forEach(p => {
                const completionPercentage = totalSubModules > 0 ? Math.round((p.completedSubModules.length / totalSubModules) * 100) : 0;
                if (completionPercentage === 100) completedCount++;
                else if (completionPercentage > 0) inProgressCount++;
            });

            return {
                courseId: course.courseId,
                title: course.title,
                assignedCount: courseProgress.length,
                inProgressCount,
                completedCount
            };
        });

        res.json(overview);
    } catch (error) {
        console.error("Get Course Progress Overview Error:", error);
        res.status(500).json({ message: 'Server error fetching course progress.' });
    }
});

app.get('/api/admin/course-report/:courseId', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    const { courseId } = req.params;
    try {
        const { Item: course } = await docClient.send(new GetCommand({ TableName: "TestifyCourses", Key: { courseId } }));
        if (!course) return res.status(404).json({ message: "Course not found." });

        const { Items: progressRecords } = await docClient.send(new ScanCommand({
            TableName: "TestifyCourseProgress",
            FilterExpression: "courseId = :cid",
            ExpressionAttributeValues: { ":cid": courseId }
        }));
        if (progressRecords.length === 0) return res.json({ courseTitle: course.title, results: [] });

        const studentEmails = [...new Set(progressRecords.map(p => p.studentEmail))];
        const keys = studentEmails.map(email => ({ email }));

        const { Responses } = await docClient.send(new BatchGetCommand({
            RequestItems: { "TestifyUsers": { Keys: keys, ProjectionExpression: "email, fullName, college" } }
        }));
        let students = Responses.TestifyUsers || [];
        
        if (req.user.role === 'Moderator') {
            const allowedColleges = new Set(req.user.assignedColleges);
            students = students.filter(student => allowedColleges.has(student.college));
        }
        
        const studentMap = new Map(students.map(s => [s.email, { fullName: s.fullName, college: s.college }]));
        const totalSubModules = course.modules.reduce((acc, mod) => acc + mod.subModules.length, 0);

        const results = progressRecords.map(p => {
            const studentInfo = studentMap.get(p.studentEmail);
            if (!studentInfo) return null;
            const completionPercentage = totalSubModules > 0 ? Math.round((p.completedSubModules.length / totalSubModules) * 100) : 0;
            return {
                studentEmail: p.studentEmail,
                studentName: studentInfo.fullName,
                college: studentInfo.college,
                status: p.status,
                completionPercentage
            };
        }).filter(Boolean);

        res.json({ courseTitle: course.title, results });
    } catch (error) {
        console.error("Get Course Report Error:", error);
        res.status(500).json({ message: 'Server error fetching course report.' });
    }
});

// GET students who completed a course but don't have a certificate (Admin)
app.get('/api/admin/course-completed-students/:courseId', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    const { courseId } = req.params;
    try {
        const { Item: course } = await docClient.send(new GetCommand({ TableName: "TestifyCourses", Key: { courseId } }));
        if (!course) return res.status(404).json({ message: 'Course not found.' });

        const totalSubModules = course.modules.reduce((acc, module) => acc + module.subModules.length, 0);
        const { Items: allProgress } = await docClient.send(new ScanCommand({
            TableName: "TestifyCourseProgress",
            FilterExpression: "courseId = :cid",
            ExpressionAttributeValues: { ":cid": courseId }
        }));
        
        const completedStudents = allProgress.filter(p => totalSubModules > 0 && (p.completedSubModules.length / totalSubModules) * 100 >= 100);
        if (completedStudents.length === 0) return res.json([]);

        const { Items: issuedCerts } = await docClient.send(new ScanCommand({
            TableName: "TestifyCertificates",
            FilterExpression: "courseId = :cid",
            ExpressionAttributeValues: { ":cid": courseId }
        }));
        const issuedEmails = new Set(issuedCerts.map(cert => cert.studentEmail));

        const eligibleStudents = completedStudents.filter(p => !issuedEmails.has(p.studentEmail));
        res.json(eligibleStudents.map(p => ({ studentEmail: p.studentEmail })));
    } catch (error) {
        console.error("Get Course Completed Students Error:", error);
        res.status(500).json({ message: 'Server error.' });
    }
});

// POST to issue course certificates (Admin)
app.post('/api/admin/issue-course-certificates', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    const { courseId, courseTitle, studentEmails } = req.body;
    try {
        if (!studentEmails || studentEmails.length === 0) return res.status(400).json({ message: "No students selected." });
        
        const keys = studentEmails.map(email => ({ email }));
        const { Responses } = await docClient.send(new BatchGetCommand({ RequestItems: { "TestifyUsers": { Keys: keys } } }));
        const students = Responses.TestifyUsers || [];
        const studentMap = new Map(students.map(s => [s.email, s.fullName]));

        for (const email of studentEmails) {
            const studentName = studentMap.get(email) || 'Student';
            const certificateId = uuidv4();
            await docClient.send(new PutCommand({
                TableName: "TestifyCertificates",
                Item: { certificateId, studentEmail: email, courseId, courseTitle, certificateType: 'Course', issuedAt: new Date().toISOString() }
            }));
            
            // This is the mailOptions object from your certificateNotificationEmail.js file
            const mailOptions = {
                from: '"TESTIFY" <testifylearning.help@gmail.com>',
                to: email,
                subject: `Congratulations! You've earned a certificate for ${courseTitle}`,
                html: `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>Certificate Earned!</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap');
        body { font-family: 'Poppins', Arial, sans-serif; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }
        a { text-decoration: none; }
        @media screen and (max-width: 600px) {
            .content-width {
                width: 90% !important;
            }
        }
    </style>
</head>
<body style="background-color: #f3f4f6; margin: 0; padding: 0;">
    <!-- Preheader text for inbox preview -->
    <span style="display:none;font-size:1px;color:#ffffff;line-height:1px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;">
        Congratulations, ${studentName}! You've earned a new certificate.
    </span>
    <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #f3f4f6;">
        <tr>
            <td align="center" style="padding: 40px 20px;">
                <!-- Main Card -->
                <table class="content-width" width="600" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #ffffff; border-radius: 12px; box-shadow: 0 10px 30px -10px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td align="center" style="padding: 30px 40px 20px; border-bottom: 1px solid #e5e7eb;">
                            <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1756037774/Gemini_Generated_Image_eu0ib0eu0ib0eu0i_z0amjh.png" 
                                 alt="Testify Logo" style="height: 50px; width: auto;">
                        </td>
                    </tr>
                    
                    <!-- Content Body -->
                    <tr>
                        <td align="center" style="padding: 40px; text-align: center;">
                             <h1 style="font-family: 'Poppins', Arial, sans-serif; font-size: 26px; font-weight: 700; color: #111827; margin: 0 0 15px;">Certificate Earned!</h1>
                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 16px; color: #4b5563; margin: 0 0 30px; line-height: 1.7;">
                                 Congratulations ${studentName}, you have successfully completed the course "<b>${courseTitle}</b>" and earned a certificate.
                             </p>
                             <a href="https://testify-io-ai.onrender.com/student/my-certificates.html" 
                                target="_blank"
                                style="display: inline-block; padding: 15px 35px; font-family: 'Poppins', Arial, sans-serif; font-size: 16px; font-weight: 600; color: #ffffff; background-color: #16a34a; border-radius: 8px; text-decoration: none;">
                                 View Certificate
                             </a>
                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 14px; color: #6b7280; margin: 30px 0 0;">
                                 Well done on your achievement!
                             </p>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td align="center" style="padding: 30px 40px; background-color: #f9fafb; border-top: 1px solid #e5e7eb; border-radius: 0 0 12px 12px;">
                            <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0 0 8px;">
                                &copy; ${new Date().getFullYear()} TESTIFY. All rights reserved.
                            </p>
                            <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0;">
                                Houston, TX, USA | <a href="mailto:testifylearning.help@gmail.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>`
            };
            
            // FIX: Added the missing line to actually send the email.
           await sendEmailWithResend(mailOptions);
        }
        res.status(200).json({ message: `Successfully issued ${studentEmails.length} certificates.` });
    } catch (error) {
        console.error("Issue Course Certificates Error:", error);
        res.status(500).json({ message: 'Server error.' });
    }
});

// --- NEW ENDPOINT: Get all certificates for Admin view ---
app.get('/api/admin/all-certificates', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    try {
        const { Items: certificates } = await docClient.send(new ScanCommand({
            TableName: "TestifyCertificates"
        }));

        if (!certificates || certificates.length === 0) {
            return res.json([]);
        }

        // Get unique student emails from the certificates
        const studentEmails = [...new Set(certificates.map(c => c.studentEmail))];

        // Fetch student details in batches
        const keys = studentEmails.map(email => ({ email }));
        const { Responses } = await docClient.send(new BatchGetCommand({
            RequestItems: {
                "TestifyUsers": {
                    Keys: keys,
                    ProjectionExpression: "email, fullName, college"
                }
            }
        }));

        const students = Responses.TestifyUsers || [];
        const studentMap = new Map(students.map(s => [s.email, s]));

        // Enrich certificate data with student details
        const enrichedCertificates = certificates.map(cert => {
            const studentInfo = studentMap.get(cert.studentEmail) || { fullName: 'N/A', college: 'N/A' };
            return {
                ...cert,
                studentName: studentInfo.fullName,
                college: studentInfo.college
            };
        });

        // Sort by most recently issued
        enrichedCertificates.sort((a, b) => new Date(b.issuedAt) - new Date(a.issuedAt));

        res.json(enrichedCertificates);

    } catch (error) {
        console.error("Get All Certificates Error:", error);
        res.status(500).json({ message: 'Server error fetching all certificates.' });
    }
});

app.get('/api/certificate/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const { Item: certificate } = await docClient.send(new GetCommand({
            TableName: "TestifyCertificates",
            Key: { certificateId: id }
        }));

        if (!certificate) {
            return res.status(404).json({ message: "Certificate not found." });
        }

        const { Item: student } = await docClient.send(new GetCommand({
            TableName: "TestifyUsers",
            Key: { email: certificate.studentEmail }
        }));

        res.json({
            ...certificate,
            studentName: student ? student.fullName : 'Student',
            profileImageUrl: student ? student.profileImageUrl : null
        });

    } catch (error) {
        console.error("Get Single Certificate Error:", error);
        res.status(500).json({ message: 'Server error fetching certificate.' });
    }
});



// =================================================================
// --- CAREERS & JOB APPLICATION ROUTES ---
// =================================================================
// Note: Ensure you have created two DynamoDB tables: 
// 1. "TestifyJobs" with "jobId" as the primary key.
// 2. "TestifyApplications" with "applicationId" as the primary key.
// =================================================================

// --- ADMIN ROUTES ---

// ADMIN ONLY: Create a new job opening
app.post('/api/admin/jobs', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { title, location, department, description } = req.body;
    if (!title || !location || !department || !description) {
        return res.status(400).json({ message: 'All job fields are required.' });
    }
    const jobId = `job_${uuidv4()}`;
    const newJob = {
        jobId,
        title,
        location,
        department,
        description,
        status: 'Open',
        createdAt: new Date().toISOString()
    };
    try {
        await docClient.send(new PutCommand({ TableName: "TestifyJobs", Item: newJob }));
        res.status(201).json({ message: 'Job opening created successfully!', job: newJob });
    } catch (error) {
        console.error("Create Job Error:", error);
        res.status(500).json({ message: 'Server error creating job opening.' });
    }
});

/**
 * @route   GET /api/admin/all-jobs
 * @desc    Admin: Get ALL job listings (open and closed)
 * @access  Private (Admin Only)
 */
app.get('/api/admin/all-jobs', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyJobs"
        }));
        Items.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        res.json(Items);
    } catch (error) {
        console.error("Get All Jobs for Admin Error:", error);
        res.status(500).json({ message: 'Server error fetching jobs.' });
    }
});

/**
 * @route   GET /api/admin/applications/:jobId
 * @desc    Admin: Get all applications for a specific job
 * @access  Private (Admin Only)
 */
app.get('/api/admin/applications/:jobId', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { jobId } = req.params;
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyApplications",
            FilterExpression: "jobId = :jid",
            ExpressionAttributeValues: { ":jid": jobId }
        }));
        Items.sort((a, b) => new Date(b.appliedAt) - new Date(a.appliedAt));
        res.json(Items);
    } catch (error) {
        console.error("Get Applications Error:", error);
        res.status(500).json({ message: 'Server error fetching applications.' });
    }
});


// --- PUBLIC & USER ROUTES ---

/**
 * @route   GET /api/careers/jobs
 * @desc    Public: Get all OPEN job listings for the careers page
 * @access  Public
 */
app.get('/api/careers/jobs', async (req, res) => {
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyJobs",
            FilterExpression: "#status = :status",
            ExpressionAttributeNames: { "#status": "status" },
            ExpressionAttributeValues: { ":status": "Open" }
        }));
        Items.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        res.json(Items);
    } catch (error) {
        console.error("Get Jobs Error:", error);
        res.status(500).json({ message: 'Server error fetching jobs.' });
    }
});

/**
 * @route   POST /api/careers/apply/:jobId
 * @desc    Public: Submit a detailed job application with file uploads
 * @access  Public
 */
app.post('/api/careers/apply/:jobId',
    upload.fields([
        { name: 'passportPhoto', maxCount: 1 },
        { name: 'resume', maxCount: 1 },
        { name: 'proofs', maxCount: 5 }
    ]),
    async (req, res) => {
        const { jobId } = req.params;
        const {
            firstName, lastName, email, phone,
            edu_10_institute, edu_10_score, edu_10_year,
            edu_12_institute, edu_12_score, edu_12_year,
            edu_btech_institute, edu_btech_score, edu_btech_year,
            edu_higher_institute, edu_higher_score, edu_higher_year,
            experiences,
            linkedinUrl, githubUrl, portfolioUrl
        } = req.body;

        if (!req.files || !req.files.passportPhoto || !req.files.resume) {
            return res.status(400).json({ message: 'Passport photo and resume are mandatory.' });
        }
        if (!firstName || !lastName || !email || !phone) {
            return res.status(400).json({ message: 'Personal details are required.' });
        }

        try {
            const { Item: job } = await docClient.send(new GetCommand({ TableName: "TestifyJobs", Key: { jobId } }));
            if (!job) {
                return res.status(404).json({ message: 'Job opening not found.' });
            }

            const uploadToCloudinary = async (file) => {
                const b64 = Buffer.from(file.buffer).toString("base64");
                const dataURI = `data:${file.mimetype};base64,${b64}`;
                return await cloudinary.uploader.upload(dataURI, {
                    folder: "applications",
                    resource_type: "auto"
                });
            };

            const photoUpload = await uploadToCloudinary(req.files.passportPhoto[0]);
            const resumeUpload = await uploadToCloudinary(req.files.resume[0]);
            
            let proofUploadUrls = [];
            if (req.files.proofs) {
                for (const file of req.files.proofs) {
                    const result = await uploadToCloudinary(file);
                    proofUploadUrls.push(result.secure_url);
                }
            }

            const applicationId = `app_${uuidv4()}`;
            const newApplication = {
                applicationId,
                jobId,
                jobTitle: job.title,
                firstName,
                lastName,
                email,
                phone,
                passportPhotoUrl: photoUpload.secure_url,
                resumeUrl: resumeUpload.secure_url,
                proofsAndCertificatesUrls: proofUploadUrls,
                education: {
                    tenth: { institute: edu_10_institute, score: edu_10_score, year: edu_10_year },
                    twelfth: { institute: edu_12_institute, score: edu_12_score, year: edu_12_year },
                    btech: { institute: edu_btech_institute, score: edu_btech_score, year: edu_btech_year },
                    higher: { institute: edu_higher_institute, score: edu_higher_score, year: edu_higher_year },
                },
                experiences: JSON.parse(experiences || '[]'),
                links: {
                    linkedin: linkedinUrl,
                    github: githubUrl,
                    portfolio: portfolioUrl
                },
                status: 'Received',
                appliedAt: new Date().toISOString()
            };

            await docClient.send(new PutCommand({ TableName: "TestifyApplications", Item: newApplication }));

            // --- EXISTING: Admin Notification Email ---
            const adminMailOptions = {
                from: '"TESTIFY Careers" <testifylearning.help@gmail.com>',
                to: 'testifylearning.help@gmail.com', // Your admin notification email
                subject: `New Application for ${job.title}: ${firstName} ${lastName}`,
                html: `<h1>Application for ${job.title}</h1><p>From: ${firstName} ${lastName} (${email})</p><p>View the full application in the admin panel.</p>`
            };
            await transporter.sendMail(adminMailOptions);

            // --- START: NEW CODE TO EMAIL APPLICANT ---
            // This block sends a confirmation email to the person who applied.
            const applicantMailOptions = {
                from: '"TESTIFY Careers" <testifylearning.help@gmail.com>',
                to: email, // The applicant's email from the form
                subject: `We've Received Your Application for ${job.title}`,
                html: `
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8" />
                        <title>Application Received</title>
                        <style>
                            @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap');
                            body { font-family: 'Poppins', Arial, sans-serif; margin: 0; padding: 0; background-color: #f3f4f6; }
                        </style>
                    </head>
                    <body style="margin: 0; padding: 0; background-color: #f3f4f6;">
                        <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #f3f4f6;">
                            <tr>
                                <td align="center" style="padding: 40px 20px;">
                                    <table width="600" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #ffffff; border-radius: 12px; box-shadow: 0 10px 30px -10px rgba(0,0,0,0.1);">
                                        <tr>
                                            <td align="center" style="padding: 30px 40px 20px; border-bottom: 1px solid #e5e7eb;">
                                                <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1756037774/Gemini_Generated_Image_eu0ib0eu0ib0eu0i_z0amjh.png" alt="Testify Logo" style="height: 50px; width: auto;">
                                            </td>
                                        </tr>
                                        <tr>
                                            <td align="center" style="padding: 40px; text-align: center;">
                                                <h1 style="font-size: 26px; font-weight: 700; color: #111827; margin: 0 0 15px;">Application Received!</h1>
                                                <p style="font-size: 16px; color: #4b5563; margin: 0 0 30px; line-height: 1.7;">
                                                    Hi ${firstName},<br><br>Thank you for your interest in the <strong>${job.title}</strong> position at Testify. We have successfully received your application.
                                                </p>
                                                <p style="font-size: 14px; color: #6b7280; margin: 30px 0 0;">
                                                    Our team will review your qualifications and get back to you if you are a good fit for the role.
                                                </p>
                                            </td>
                                        </tr>
                                        <tr>
                                            <td align="center" style="padding: 30px 40px; background-color: #f9fafb; border-top: 1px solid #e5e7eb; border-radius: 0 0 12px 12px;">
                                                <p style="font-size: 12px; color: #6b7280; margin: 0;">&copy; ${new Date().getFullYear()} TESTIFY. All rights reserved.</p>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
                    </body>
                    </html>
                `
            };
            await transporter.sendMail(applicantMailOptions);
            // --- END: NEW CODE TO EMAIL APPLICANT ---

            res.status(201).json({ message: 'Application submitted successfully! We will be in touch.' });

        } catch (error) {
            console.error("Apply Job Error:", error);
            res.status(500).json({ message: 'Server error submitting application.' });
        }
    }
);
/**
 * @route   GET /api/student/my-applications
 * @desc    Student: Get all their past applications
 * @access  Private (Student)
 */
app.get('/api/student/my-applications', authMiddleware, async (req, res) => {
    // Assuming the authMiddleware populates req.user.email for the logged-in student
    const studentEmail = req.user.email;
    if (!studentEmail) {
        return res.status(401).json({ message: 'Authentication required.' });
    }

    try {
        // UPDATED: Changed from Scan to a more efficient Query on the new index.
        const { Items } = await docClient.send(new QueryCommand({
            TableName: "TestifyApplications",
            IndexName: "email-index", // Use the newly created Global Secondary Index
            KeyConditionExpression: "email = :email",
            ExpressionAttributeValues: { ":email": studentEmail }
        }));
        
        Items.sort((a, b) => new Date(b.appliedAt) - new Date(a.appliedAt));
        
        res.json(Items);
    } catch (error) {
        console.error("Get My Applications Error:", error);
        res.status(500).json({ message: 'Server error fetching your applications.' });
    }
});

/**
 * @route   GET /api/check-auth
 * @desc    Verify user's token and return user data if valid
 * @access  Private
 */
// app.get('/api/check-auth', authMiddleware, async (req, res) => {
//     // The authMiddleware handles token verification. If it passes, the token is valid.
//     // We then fetch the user's latest data from the database to ensure it's fresh.
//     try {
//         const { Item } = await docClient.send(new GetCommand({
//             TableName: "TestifyUsers", // Assuming your users are in 'TestifyUsers'
//             Key: { email: req.user.email }
//         }));
//         if (!Item) {
//             return res.status(404).json({ message: 'User not found.' });
//         }
//         const { password, ...userData } = Item; // Exclude password from the response
//         res.json(userData);
//     } catch (error) {
//         console.error("Check Auth Error:", error);
//         res.status(500).json({ message: 'Server error during authentication check.' });
//     }
// });

app.patch('/api/admin/applications/status', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { applicationId, status } = req.body;
    if (!applicationId || !status) {
        return res.status(400).json({ message: 'Application ID and new status are required.' });
    }
    const validStatuses = ['Received', 'Under Review', 'Interview', 'Hired', 'Rejected'];
    if (!validStatuses.includes(status)) {
        return res.status(400).json({ message: 'Invalid status value.' });
    }
    try {
        await docClient.send(new UpdateCommand({
            TableName: "TestifyApplications",
            Key: { applicationId },
            UpdateExpression: "set #status = :s",
            ExpressionAttributeNames: { "#status": "status" },
            ExpressionAttributeValues: { ":s": status }
        }));
        res.json({ message: 'Application status updated successfully.' });
    } catch (error) {
        console.error("Update Application Status Error:", error);
        res.status(500).json({ message: 'Server error updating application status.' });
    }
});


app.get('/api/check-auth', authMiddleware, async (req, res) => {
    // The authMiddleware already verifies the token and populates req.user.
    // This endpoint re-fetches user data to ensure it's fresh (e.g., role changes, blocks).
    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: "TestifyUsers",
            Key: { email: req.user.email }
        }));

        if (!Item) {
            // This case is unlikely if the token is valid, but it's a good safeguard.
            return res.status(404).json({ message: 'User associated with token not found.' });
        }
        
        // Exclude sensitive information like the password hash before sending the user object.
        const { password, ...userData } = Item;
        res.json(userData);

    } catch (error) {
        console.error("Check Auth Error:", error);
        res.status(500).json({ message: 'Server error during authentication check.' });
    }
});
app.get('/api/public/my-applications', async (req, res) => {
    const { email } = req.query;
    if (!email) {
        return res.status(400).json({ message: 'Email query parameter is required.' });
    }

    try {
        // Use the efficient GSI to query applications by email
        const { Items } = await docClient.send(new QueryCommand({
            TableName: "TestifyApplications",
            IndexName: "email-index", 
            KeyConditionExpression: "email = :email",
            ExpressionAttributeValues: { ":email": email.toLowerCase() }
        }));
        
        Items.sort((a, b) => new Date(b.appliedAt) - new Date(a.appliedAt));
        
        res.json(Items);
    } catch (error) {
        console.error("Get Public Applications Error:", error);
        res.status(500).json({ message: 'Server error fetching your applications.' });
    }
});
// --- NEW: OTP-based authentication for viewing applications ---

/**
 * @route   POST /api/careers/send-view-otp
 * @desc    Public: Send an OTP to a user's email to let them view their applications.
 * @access  Public
 */
app.post('/api/careers/send-view-otp', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ message: 'Email is required.' });
    }
    const emailLower = email.toLowerCase();

    try {
        // First, check if any applications exist for this email to prevent unnecessary OTP sends.
        const { Items } = await docClient.send(new QueryCommand({
            TableName: "TestifyApplications",
            IndexName: "email-index",
            KeyConditionExpression: "email = :email",
            ExpressionAttributeValues: { ":email": emailLower }
        }));

        if (!Items || Items.length === 0) {
            return res.status(404).json({ message: 'No applications found for this email address.' });
        }

        // Generate and store OTP (using the existing in-memory store)
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expirationTime = Date.now() + 5 * 60 * 1000; // 5-minute validity

        // The 'otpStore' object should already be defined at the top of your backend.js
        otpStore[emailLower] = { otp, expirationTime };
        console.log(`Generated application view OTP for ${email}: ${otp}`);

        // Send the OTP via email
        const mailOptions = {
            from: '"TESTIFY" <testifylearning.help@gmail.com>',
            to: email,
            subject: 'Your Application Status Verification Code',
            html: `
                <div style="font-family: Arial, sans-serif; text-align: center; color: #333;">
                    <h2>TESTIFY Application Status</h2>
                    <p>Your verification code is:</p>
                    <p style="font-size: 24px; font-weight: bold; letter-spacing: 3px; color: #4F46E5;">${otp}</p>
                    <p>This code will expire in 5 minutes.</p>
                </div>
            `
        };

       await sendEmailWithResend(mailOptions);
        res.status(200).json({ message: 'A verification code has been sent to your email.' });

    } catch (error) {
        console.error("Send Application View OTP Error:", error);
        res.status(500).json({ message: 'Server error. Please try again later.' });
    }
});

/**
 * @route   POST /api/careers/verify-view-otp
 * @desc    Public: Verify OTP and fetch all applications for that email.
 * @access  Public
 */
app.post('/api/careers/verify-view-otp', async (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) {
        return res.status(400).json({ message: 'Email and verification code are required.' });
    }
    const emailLower = email.toLowerCase();

    // Verify the OTP
    const storedOtpData = otpStore[emailLower];
    if (!storedOtpData || storedOtpData.otp !== otp || Date.now() > storedOtpData.expirationTime) {
        return res.status(400).json({ message: 'Invalid or expired verification code.' });
    }

    try {
        // OTP is valid, remove it to prevent reuse
        delete otpStore[emailLower];

        // Fetch applications using the GSI for efficiency
        const { Items: applications } = await docClient.send(new QueryCommand({
            TableName: "TestifyApplications",
            IndexName: "email-index",
            KeyConditionExpression: "email = :email",
            ExpressionAttributeValues: { ":email": emailLower }
        }));

        if (!applications || applications.length === 0) {
            return res.json([]);
        }

        // Fetch job details to get the application deadline for the "Edit" button logic
        const jobIds = [...new Set(applications.map(app => app.jobId))];
        const keys = jobIds.map(jobId => ({ jobId }));
        
        const { Responses } = await docClient.send(new BatchGetCommand({
            RequestItems: { "TestifyJobs": { Keys: keys } }
        }));
        
        const jobs = Responses.TestifyJobs || [];
        const jobDeadlineMap = new Map(jobs.map(j => [j.jobId, j.applicationDeadline]));

        // Enrich application data with the deadline
        const enrichedApplications = applications.map(app => ({
            ...app,
            jobDeadline: jobDeadlineMap.get(app.jobId) || null
        }));

        enrichedApplications.sort((a, b) => new Date(b.appliedAt) - new Date(a.appliedAt));
        
        res.status(200).json(enrichedApplications);

    } catch (error) {
        console.error("Verify OTP & Fetch Applications Error:", error);
        res.status(500).json({ message: 'Server error fetching applications.' });
    }
});
// =================================================================
// --- END OF CAREERS ROUTES ---
// =================================================================

// Add these new endpoints to your backend.js file.
// You can place them after your existing /api/assign-test endpoint.

app.post('/api/fullscreen-tests', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    
    const { testTitle, duration, totalMarks, passingPercentage, questions } = req.body;
    const testId = uuidv4();

    const newTest = {
        testId,
        title: testTitle,
        duration,
        totalMarks,
        passingPercentage,
        questions,
        testType: 'fullscreen', // Differentiate from AI proctored tests
        createdAt: new Date().toISOString(),
        status: 'Not Assigned',
        // Ensure this property exists to avoid future errors
        autoIssueCertificates: false 
    };

    try {
        await docClient.send(new PutCommand({ TableName: "TestifyTests", Item: newTest }));
        res.status(201).json({ message: 'Full Screen Test created successfully!', test: newTest });
    } catch (error) {
        console.error("Create Full Screen Test Error:", error);
        res.status(500).json({ message: 'Server error creating test.' });
    }
});

// Get all Full Screen tests (Admin)
app.get('/api/fullscreen-tests', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    try {
        const { Items } = await docClient.send(new ScanCommand({ 
            TableName: "TestifyTests",
            FilterExpression: "attribute_exists(testType) AND testType = :type",
            ExpressionAttributeValues: {
                ":type": "fullscreen"
            }
        }));
        res.json(Items);
    } catch (error) {
        console.error("Get Full Screen Tests Error:", error);
        res.status(500).json({ message: 'Server error fetching tests.' });
    }
});

// Get Full Screen test results (Admin)
app.get('/api/fullscreen-results/:testId', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    const { testId } = req.params;
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyResults",
            FilterExpression: "testId = :tid",
            ExpressionAttributeValues: {
                ":tid": testId
            }
        }));

        const studentEmails = [...new Set(Items.map(item => item.studentEmail))];
        if (studentEmails.length === 0) {
            return res.json([]);
        }

        const keys = studentEmails.map(email => ({ email }));
        const { Responses } = await docClient.send(new BatchGetCommand({
            RequestItems: { "TestifyUsers": { Keys: keys } }
        }));
        const students = Responses.TestifyUsers || [];
        const studentMap = new Map(students.map(s => [s.email, { fullName: s.fullName, college: s.college }]));

        const resultsWithNames = Items.map(result => ({
            ...result,
            studentName: studentMap.get(result.studentEmail)?.fullName || 'Unknown',
            college: studentMap.get(result.studentEmail)?.college || 'Unknown'
        }));

        res.json(resultsWithNames);
    } catch (error) {
        console.error("Get Full Screen Test Results Error:", error);
        res.status(500).json({ message: 'Server error fetching results.' });
    }
});

// NEW: Endpoint specifically for assigning Full Screen tests
app.post('/api/assign-fullscreen-test', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    // This endpoint is simpler and does not handle 'autoIssueCertificates'.
    const { testId, testName, colleges, studentEmails, sendEmail } = req.body;

    try {
        let studentsToNotify = [];

        // Logic for assigning to specific students (allows retakes)
        if (studentEmails && studentEmails.length > 0) {
            for (const email of studentEmails) {
                // Delete existing result to allow retake
                const { Items: existingResults } = await docClient.send(new ScanCommand({
                    TableName: "TestifyResults",
                    FilterExpression: "studentEmail = :email AND testId = :tid",
                    ExpressionAttributeValues: { ":email": email, ":tid": testId }
                }));

                if (existingResults && existingResults.length > 0) {
                    const deleteRequests = existingResults.map(result => ({ DeleteRequest: { Key: { resultId: result.resultId } } }));
                    const batches = [];
                    for (let i = 0; i < deleteRequests.length; i += 25) {
                        batches.push(deleteRequests.slice(i, i + 25));
                    }
                    for (const batch of batches) {
                        await docClient.send(new BatchWriteCommand({ RequestItems: { "TestifyResults": batch } }));
                    }
                }

                // Create an assignment record if one doesn't exist
                const { Items: existingAssignments } = await docClient.send(new ScanCommand({
                    TableName: "TestifyAssignments",
                    FilterExpression: "studentEmail = :email AND testId = :tid",
                    ExpressionAttributeValues: { ":email": email, ":tid": testId }
                }));
                if (!existingAssignments || existingAssignments.length === 0) {
                    await docClient.send(new PutCommand({
                        TableName: "TestifyAssignments",
                        Item: { assignmentId: uuidv4(), testId, studentEmail: email, assignedAt: new Date().toISOString() }
                    }));
                }
            }
            studentsToNotify = studentEmails;
        } 
        // Logic for assigning to entire colleges
        else if (colleges && colleges.length > 0) {
            if (req.user.role === 'Moderator') {
                const isAllowed = colleges.every(college => req.user.assignedColleges.includes(college));
                if (!isAllowed) {
                    return res.status(403).json({ message: 'You can only assign tests to your assigned colleges.' });
                }
            }
            
            const filterExpression = colleges.map((_, index) => `college = :c${index}`).join(' OR ');
            const expressionAttributeValues = colleges.reduce((acc, college, index) => ({ ...acc, [`:c${index}`]: college }), {});
            
            const { Items: studentsInColleges } = await docClient.send(new ScanCommand({
                TableName: "TestifyUsers",
                FilterExpression: filterExpression,
                ExpressionAttributeValues: expressionAttributeValues
            }));

            if (studentsInColleges.length > 0) {
                const assignmentWrites = studentsInColleges.map(student => ({
                    PutRequest: { Item: { assignmentId: uuidv4(), testId, studentEmail: student.email, assignedAt: new Date().toISOString() } }
                }));
                const batches = [];
                for (let i = 0; i < assignmentWrites.length; i += 25) {
                    batches.push(assignmentWrites.slice(i, i + 25));
                }
                for (const batch of batches) {
                    await docClient.send(new BatchWriteCommand({ RequestItems: { "TestifyAssignments": batch } }));
                }
            }
            studentsToNotify = studentsInColleges.map(s => s.email);
        }

        // Mark the test as 'Assigned'. This update is safe for Full Screen tests.
        await docClient.send(new UpdateCommand({
            TableName: "TestifyTests",
            Key: { testId },
            UpdateExpression: "set #status = :status",
            ExpressionAttributeNames: { "#status": "status" },
            ExpressionAttributeValues: { ":status": `Assigned` }
        }));

        // Send email notifications
        if (sendEmail && studentsToNotify.length > 0) {
            const mailOptions = {
                from: '"TESTIFY" <testifylearning.help@gmail.com>',
                to: studentsToNotify.join(','),
                subject: `New Full Screen Test Assigned: ${testName}`,
                html: `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>New Test Assigned</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap');
        body { font-family: 'Poppins', Arial, sans-serif; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }
        a { text-decoration: none; }
        @media screen and (max-width: 600px) {
            .content-width { width: 90% !important; }
        }
    </style>
</head>
<body style="background-color: #f3f4f6; margin: 0; padding: 0;">
    <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #f3f4f6;">
        <tr>
            <td align="center" style="padding: 40px 20px;">
                <table class="content-width" width="600" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #ffffff; border-radius: 12px; box-shadow: 0 10px 30px -10px rgba(0,0,0,0.1);">
                    <tr>
                        <td align="center" style="padding: 30px 40px 20px; border-bottom: 1px solid #e5e7eb;">
                            <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1756037774/Gemini_Generated_Image_eu0ib0eu0ib0eu0i_z0amjh.png" alt="Testify Logo" style="height: 50px; width: auto;">
                        </td>
                    </tr>
                    <tr>
                        <td align="center" style="padding: 40px; text-align: center;">
                             <h1 style="font-family: 'Poppins', Arial, sans-serif; font-size: 26px; font-weight: 700; color: #111827; margin: 0 0 15px;">New Test Assigned</h1>
                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 16px; color: #4b5563; margin: 0 0 30px; line-height: 1.7;">
                                 A new full screen test, "<b>${testName}</b>", has been assigned to you. Please log in to your dashboard to take the test.
                             </p>
                             <a href="https://testify-io-ai.onrender.com/student/fullscreen-test.html" 
                                target="_blank"
                                style="display: inline-block; padding: 15px 35px; font-family: 'Poppins', Arial, sans-serif; font-size: 16px; font-weight: 600; color: #ffffff; background-color: #3b82f6; border-radius: 8px; text-decoration: none;">
                                 Go to Full Screen Tests
                             </a>
                             <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 14px; color: #6b7280; margin: 30px 0 0;">
                                 Good luck!
                             </p>
                        </td>
                    </tr>
                    <tr>
                        <td align="center" style="padding: 30px 40px; background-color: #f9fafb; border-top: 1px solid #e5e7eb; border-radius: 0 0 12px 12px;">
                            <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0 0 8px;">
                                &copy; ${new Date().getFullYear()} TESTIFY. All rights reserved.
                            </p>
                            <p style="font-family: 'Poppins', Arial, sans-serif; font-size: 12px; color: #6b7280; margin: 0;">
                                Houston, TX, USA | <a href="mailto:testifylearning.help@gmail.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>`
            };
           await sendEmailWithResend(mailOptions);
        }
        res.status(200).json({ message: 'Full Screen Test assigned successfully!' });
    } catch (error) {
        console.error("Assign Full Screen Test Error:", error);
        res.status(500).json({ message: 'Server error assigning test.' });
    }
});


// Add these endpoints to your main backend.js file

// GET a single fullscreen test's details (for modification page)
app.get('/api/fullscreen-tests/:id', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: "TestifyTests",
            Key: { testId: req.params.id }
        }));
        if (Item && Item.testType === 'fullscreen') {
            res.json(Item);
        } else {
            res.status(404).json({ message: 'Full screen test not found.' });
        }
    } catch (error) {
        console.error("Get Single Full Screen Test Error:", error);
        res.status(500).json({ message: 'Server error fetching test.' });
    }
});

// PUT (update) a fullscreen test
app.put('/api/fullscreen-tests/:id', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    
    const { testTitle, duration, totalMarks, passingPercentage, questions } = req.body;
    const testId = req.params.id;

    try {
        const { Item: existingTest } = await docClient.send(new GetCommand({
            TableName: "TestifyTests",
            Key: { testId }
        }));
        if (!existingTest || existingTest.testType !== 'fullscreen') {
            return res.status(404).json({ message: 'Full screen test not found for update.' });
        }

        const updatedTest = {
            ...existingTest, 
            title: testTitle,
            duration,
            totalMarks,
            passingPercentage,
            questions
        };

        await docClient.send(new PutCommand({
            TableName: "TestifyTests",
            Item: updatedTest
        }));
        res.status(200).json({ message: 'Test updated successfully!', test: updatedTest });
    } catch (error) {
        console.error("Update Full Screen Test Error:", error);
        res.status(500).json({ message: 'Server error updating test.' });
    }
});
// ... existing code ...

// METT?///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
async function getZoomAccessToken() {
    try {
        const response = await fetch(`https://zoom.us/oauth/token?grant_type=account_credentials&account_id=${ZOOM_ACCOUNT_ID}`, {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${Buffer.from(`${ZOOM_CLIENT_ID}:${ZOOM_CLIENT_SECRET}`).toString('base64')}`
            }
        });
        if (!response.ok) {
            const errorBody = await response.json();
            console.error("Zoom Token Error:", errorBody);
            throw new Error('Failed to get Zoom access token');
        }
        const data = await response.json();
        return data.access_token;
    } catch (error) {
        console.error("Error in getZoomAccessToken:", error);
        throw error;
    }
}

/**
 * Creates a new Zoom meeting.
 * @param {object} meetingDetails Details for the meeting.
 */
async function createZoomMeeting(meetingDetails) {
    const accessToken = await getZoomAccessToken(); // Use the new function to get a token
    const zoomApiUrl = 'https://api.zoom.us/v2/users/me/meetings';

    const payload = {
        topic: meetingDetails.topic,
        type: 2, // Scheduled meeting
        start_time: meetingDetails.startTime,
        duration: meetingDetails.duration, // in minutes
        timezone: 'Asia/Kolkata',
        settings: {
            host_video: true,
            participant_video: true,
            join_before_host: false,
            mute_upon_entry: true,
            use_pmi: false,
            approval_type: 0,
            registration_type: 1,
            audio: 'both',
            auto_recording: 'none',
        },
    };

    const response = await fetch(zoomApiUrl, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${accessToken}`, // Use the Bearer token
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
    });

    if (!response.ok) {
        const errorBody = await response.json();
        console.error("Zoom API Error:", errorBody);
        throw new Error(`Zoom API failed with status: ${response.status}`);
    }

    return await response.json();
}

// ... (The rest of your backend.js code remains the same from here) ...

// --- AUTHENTICATION MIDDLEWARE [MODIFIED] ---
// const authMiddleware = async (req, res, next) => {
//     const token = req.header('x-auth-token');
//     if (!token) {
//         return res.status(401).json({ message: 'No token, authorization denied' });
//     }
//     try {
//         const decoded = jwt.verify(token, JWT_SECRET);
//         req.user = decoded.user;

//         const { Item } = await docClient.send(new GetCommand({
//             TableName: "TestifyUsers",
//             Key: { email: req.user.email }
//         }));

//         if (!Item) {
//             return res.status(404).json({ message: 'User not found.' });
//         }

//         if (Item.isBlocked) {
//             return res.status(403).json({ message: 'Your account has been blocked by the administrator.' });
//         }

//         if (Item.role === 'Moderator') {
//             req.user.assignedColleges = Item.assignedColleges || [];
//         }


//         next();
//     } catch (e) {
//         res.status(401).json({ message: 'Token is not valid' });
//     }
// };

// const adminOrModeratorAuth = (req, res, next) => {
//     if (req.user.role !== 'Admin' && req.user.role !== 'Moderator') {
//         return res.status(403).json({ message: 'Access denied.' });
//     }
//     next();
// };


app.post('/api/meetings/schedule', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    const { title, description, startTime, durationMinutes, colleges, studentEmails, sendEmail } = req.body;
    const scheduledBy = req.user.email;

    if (!title || !startTime || !durationMinutes || (!colleges && !studentEmails)) {
        return res.status(400).json({ message: 'Missing required fields for scheduling a meeting.' });
    }
    try {
        const meetingDetails = {
            topic: title,
            startTime: new Date(startTime).toISOString(),
            duration: durationMinutes,
        };
        const zoomMeeting = await createZoomMeeting(meetingDetails);
        const meetLink = zoomMeeting.join_url;
        let targetAttendees = [];
        if (studentEmails && studentEmails.length > 0) {
            targetAttendees = studentEmails;
        } else if (colleges && colleges.length > 0) {
             const filterExpression = colleges.map((_, index) => `college = :c${index}`).join(' OR ');
             const expressionAttributeValues = {};
             colleges.forEach((college, index) => { expressionAttributeValues[`:c${index}`] = college; });
             const { Items } = await docClient.send(new ScanCommand({
                 TableName: "TestifyUsers",
                 FilterExpression: filterExpression,
                 ExpressionAttributeValues: expressionAttributeValues,
                 ProjectionExpression: "email"
             }));
             targetAttendees = Items.map(s => s.email);
        }
        if (targetAttendees.length === 0) {
            return res.status(400).json({ message: 'No students found for the selected criteria.' });
        }
        const meetingId = `meet_${uuidv4()}`;
        const newMeeting = {
            testId: meetingId,
            title, description, duration: durationMinutes, startTime, isMeeting: true,
            meetLink, scheduledBy, attendees: [], createdAt: new Date().toISOString()
        };
        await docClient.send(new PutCommand({ TableName: "TestifyTests", Item: newMeeting }));
        const assignmentWrites = targetAttendees.map(email => ({
            PutRequest: {
                Item: {
                    assignmentId: uuidv4(),
                    testId: meetingId,
                    studentEmail: email,
                    assignedAt: new Date().toISOString()
                }
            }
        }));
        const batches = [];
        for (let i = 0; i < assignmentWrites.length; i += 25) {
            batches.push(assignmentWrites.slice(i, i + 25));
        }
        for (const batch of batches) {
            await docClient.send(new BatchWriteCommand({ RequestItems: { "TestifyAssignments": batch } }));
        }
        if (sendEmail && targetAttendees.length > 0) {
            const mailOptions = {
                from: '"TESTIFY" <testifylearning.help@gmail.com>',
                to: targetAttendees.join(','),
                subject: `Invitation: ${title}`,
                html: `<p>You have been invited to a meeting: <strong>${title}</strong>.</p><p>It is scheduled for ${new Date(startTime).toLocaleString()}. Please check your dashboard to join.</p>`
            };
           await sendEmailWithResend(mailOptions);
        }
        res.status(201).json({ message: 'Zoom meeting scheduled and assigned successfully!', meeting: newMeeting });
    } catch (error) {
        console.error("Schedule Meeting Error:", error);
        res.status(500).json({ message: 'Server error scheduling meeting.' });
    }
});

// The remaining meeting endpoints do not need to change as they only interact with your DynamoDB tables.

// Endpoint for students to get their assigned meetings.
app.get('/api/student/meetings', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });

    try {
        const { Items: assignments } = await docClient.send(new ScanCommand({
            TableName: "TestifyAssignments",
            FilterExpression: "studentEmail = :email",
            ExpressionAttributeValues: { ":email": req.user.email }
        }));

        if (!assignments || assignments.length === 0) return res.json([]);
        
        const meetingIds = assignments.map(a => a.testId).filter(id => id && id.startsWith('meet_'));
        if (meetingIds.length === 0) return res.json([]);

        const keys = [...new Set(meetingIds)].map(testId => ({ testId }));
        const { Responses } = await docClient.send(new BatchGetCommand({
            RequestItems: { "TestifyTests": { Keys: keys } }
        }));
        
        const meetings = Responses.TestifyTests ? Responses.TestifyTests.filter(item => item.isMeeting === true) : [];
        meetings.sort((a, b) => new Date(a.startTime) - new Date(b.startTime));
        
        res.json(meetings);
    } catch (error) {
        console.error("Get Student Meetings Error:", error);
        res.status(500).json({ message: 'Server error fetching meetings.' });
    }
});

// Endpoint for students to "check-in" to a meeting. This records their attendance.
app.post('/api/meetings/:meetingId/join', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    
    const { meetingId } = req.params;
    const studentEmail = req.user.email;
    const studentName = req.user.fullName;

    try {
        const { Item: meeting } = await docClient.send(new GetCommand({
            TableName: "TestifyTests",
            Key: { testId: meetingId }
        }));
        
        if (!meeting || !meeting.isMeeting) return res.status(404).json({ message: 'Meeting not found.' });

        const alreadyJoined = meeting.attendees && meeting.attendees.some(att => att.email === studentEmail);
        if (!alreadyJoined) {
            const attendeeInfo = {
                email: studentEmail,
                name: studentName,
                joinTime: new Date().toISOString()
            };
            await docClient.send(new UpdateCommand({
                TableName: "TestifyTests",
                Key: { testId: meetingId },
                UpdateExpression: "SET attendees = list_append(if_not_exists(attendees, :empty_list), :newAttendee)",
                ExpressionAttributeValues: { 
                    ":newAttendee": [attendeeInfo],
                    ":empty_list": []
                }
            }));
        }
        
        res.status(200).json({ message: 'Attendance recorded.' });
    } catch (error) {
        console.error("Join Meeting Error:", error);
        res.status(500).json({ message: 'Server error recording attendance.' });
    }
});


// Endpoint for Admins to get all scheduled meetings.
app.get('/api/admin/meetings', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyTests",
            FilterExpression: "isMeeting = :true",
            ExpressionAttributeValues: { ":true": true }
        }));
        Items.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        res.json(Items);
    } catch (error) {
        console.error("Get All Meetings Error:", error);
        res.status(500).json({ message: 'Server error fetching meetings.' });
    }
});

// Endpoint for Admins to get the list of attendees for a specific meeting.
app.get('/api/admin/meetings/:meetingId/attendees', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    const { meetingId } = req.params;
    try {
         const { Item: meeting } = await docClient.send(new GetCommand({
            TableName: "TestifyTests",
            Key: { testId: meetingId }
        }));
        if (!meeting || !meeting.isMeeting) return res.status(404).json({ message: 'Meeting not found.' });
        
        const attendees = meeting.attendees || [];
        if (attendees.length === 0) {
            return res.json([]);
        }

        // Get all unique attendee emails
        const attendeeEmails = [...new Set(attendees.map(att => att.email))];

        // Fetch user details from TestifyUsers table to get their college
        const keys = attendeeEmails.map(email => ({ email }));
        const { Responses } = await docClient.send(new BatchGetCommand({
            RequestItems: {
                "TestifyUsers": {
                    Keys: keys,
                    ProjectionExpression: "email, college" // Only fetch what we need
                }
            }
        }));

        const users = Responses.TestifyUsers || [];
        const collegeMap = new Map(users.map(u => [u.email, u.college]));

        // Enrich the attendee list with college information
        const enrichedAttendees = attendees.map(att => ({
            ...att,
            college: collegeMap.get(att.email) || 'N/A' // Add college, with a fallback
        }));
        
        res.json(enrichedAttendees); // Send the enriched list
    } catch (error) {
        console.error("Get Attendees Error:", error);
        res.status(500).json({ message: 'Server error fetching attendees.' });
    }
});


app.post('/api/certificates-by-email', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ message: "Email is required." });
    }

    try {
        // 1. Find all certificates for the given email using the GSI
        const { Items: certificates } = await docClient.send(new QueryCommand({
            TableName: "TestifyCertificates",
            IndexName: "StudentEmailIndex", // Assumes a GSI with studentEmail as the partition key
            KeyConditionExpression: "studentEmail = :email",
            ExpressionAttributeValues: { ":email": email.toLowerCase() }
        }));

        if (!certificates || certificates.length === 0) {
            return res.status(404).json({ message: "No certificates found for this email address." });
        }

        // 2. Since we have the certificates, we can get the student details once.
        const { Item: student } = await docClient.send(new GetCommand({
            TableName: "TestifyUsers",
            Key: { email: email.toLowerCase() }
        }));

        // 3. Enrich each certificate with the student's details, even if student is not found
        const enrichedCertificates = certificates.map(cert => ({
            ...cert,
            studentName: student ? student.fullName : 'Unknown Student',
            college: student ? student.college : 'N/A',
            rollNumber: student ? student.rollNumber : 'N/A',
            profileImageUrl: student ? student.profileImageUrl : null
        }));
        
        res.json(enrichedCertificates);

    } catch (error) {
        console.error("Verify Certificate by Email Error:", error);
        res.status(500).json({ message: 'Server error verifying certificates by email.' });
    }
});

app.get('/api/student/test-attempts/:testId', authMiddleware, async (req, res) => {
    const { testId } = req.params;
    const studentEmail = req.user.email;
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyResults",
            FilterExpression: "testId = :tid AND studentEmail = :email",
            ExpressionAttributeValues: {
                ":tid": testId,
                ":email": studentEmail
            }
        }));
        res.json({ attempts: Items.length });
    } catch (error) {
        console.error("Get Test Attempts Error:", error);
        res.status(500).json({ message: 'Server error fetching attempt count.' });
    }
});



// --- SERVER START ---
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});


