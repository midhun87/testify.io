// backend_moderator.js
// --- IMPORTS ---
require('dotenv').config();
const express = require('express');
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, PutCommand, GetCommand, ScanCommand, QueryCommand, UpdateCommand, BatchGetCommand, DeleteCommand } = require("@aws-sdk/lib-dynamodb");
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
const { BatchWriteCommand } = require("@aws-sdk/lib-dynamodb");
const { RekognitionClient, CompareFacesCommand } = require("@aws-sdk/client-rekognition");


// --- INITIALIZATION ---
const app = express();
const PORT = 3000;
const JWT_SECRET = 'your-super-secret-key-for-jwt-in-production';

// --- AWS DYNAMODB CLIENT SETUP ---
const client = new DynamoDBClient({
    region: 'ap-south-1',
    credentials: {
        accessKeyId: 'AKIATCKAN7T2MYCBT7OD',
        secretAccessKey: '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'
    }
});
const docClient = DynamoDBDocumentClient.from(client);

// --- NODEMAILER TRANSPORTER SETUP ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'testifylearning.help@gmail.com',
        pass: 'gkiz belc koar elxi '
    }
});

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


// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));
app.use('/moderator', express.static(path.join(__dirname, 'public/moderator')));


// --- AUTHENTICATION MIDDLEWARE [MODIFIED] ---
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


// =================================================================
// --- OTP IMPLEMENTATION ---
// =================================================================
// In-memory store for OTPs. In a real application, use a database with TTL.
const otpStore = {};

// NEW ENDPOINT: Send OTP to user's email
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
        const expirationTime = Date.now() + 5 * 60 * 1000; // 5 minutes from now

        otpStore[email.toLowerCase()] = { otp, expirationTime };
        console.log(`Generated OTP for ${email}: ${otp}`);

        const mailOptions = {
            from: '"TESTIFY" <testifylearning.help@gmail.com>',
            to: email,
            subject: 'TESTIFY Account Verification',
            html: `<p>Your OTP for TESTIFY account creation is: <strong>${otp}</strong></p>
                   <p>This OTP is valid for 5 minutes. Do not share it with anyone.</p>`
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({ message: 'OTP sent successfully. Please check your email.' });
    } catch (error) {
        console.error("Send OTP Error:", error);
        res.status(500).json({ message: 'Server error sending OTP. Please try again.' });
    }
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
            to: studentEmail,
            subject: `Congratulations! You've earned a certificate for ${testTitle}`,
            html: `
                <div style="font-family: Arial, sans-serif; border: 5px solid #4F46E5; padding: 20px; text-align: center;">
                    <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1756037774/Gemini_Generated_Image_eu0ib0eu0ib0eu0i_z0amjh.png" alt="TESTIFY Logo" style="width: 80px; margin-bottom: 20px;">
                    <h1 style="color: #4F46E5;">Certificate of Achievement</h1>
                    <p style="font-size: 18px;">This is to certify that</p>
                    <h2 style="font-size: 24px; color: #111827; margin: 10px 0;">${studentName}</h2>
                    <p style="font-size: 18px;">has successfully completed the test</p>
                    <h3 style="font-size: 22px; color: #111827; margin: 10px 0;">${testTitle}</h3>
                    <p style="font-size: 16px;">on ${issueDate}</p>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
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

        if (studentEmails && studentEmails.length > 0) {
            for (const email of studentEmails) {
                const assignmentId = uuidv4();
                await docClient.send(new PutCommand({
                    TableName: "TestifyAssignments",
                    Item: { assignmentId, testId, studentEmail: email, assignedAt: new Date().toISOString() }
                }));
            }
            studentsToNotify = studentEmails;
        } 
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
            const { Items } = await docClient.send(new ScanCommand({
                TableName: "TestifyUsers",
                FilterExpression: filterExpression,
                ExpressionAttributeValues: expressionAttributeValues
            }));
            studentsToNotify = Items.map(s => s.email);
        }

        if (req.user.role === 'Admin') {
            await docClient.send(new UpdateCommand({
                TableName: "TestifyTests",
                Key: { testId },
                UpdateExpression: "set #status = :status, #autoIssue = :autoIssue",
                ExpressionAttributeNames: { "#status": "status", "#autoIssue": "autoIssueCertificates" },
                ExpressionAttributeValues: { ":status": `Assigned`, ":autoIssue": autoIssueCertificates }
            }));
        }

        if (sendEmail && studentsToNotify.length > 0) {
            const mailOptions = {
                from: '"TESTIFY" <testifylearning.help@gmail.com>',
                to: studentsToNotify.join(','),
                subject: `New Test Assigned: ${testName}`,
                html: `<p>Hello,</p><p>A new test, "<b>${testName}</b>", has been assigned to you. Please log in to your TESTIFY dashboard to take the test.<a href="https://testify-io-ai.onrender.com/student/take-test.html">Click here to login</a></p><p>Best regards,<br/>The TESTIFY Team</p>`
            };
            await transporter.sendMail(mailOptions);
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
            const mailOptions = {
                from: '"TESTIFY" <testifylearning.help@gmail.com>',
                to: studentEmails.join(','),
                subject: `New Course Assigned: ${course.title}`,
                html: `<p>Hello,</p><p>A new course, "<b>${course.title}</b>", has been assigned to you. Please log in to your TESTIFY dashboard to begin learning.</p><p>Best regards,<br/>The TESTIFY Team</p>`
            };
            await transporter.sendMail(mailOptions);
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
                    html: `<p>Congratulations!</p><p>You have completed the course "<b>${course.title}</b>". The final test, "<b>${test.title}</b>", is now available in your dashboard.</p><p>Best of luck!</p>`
                };
                await transporter.sendMail(mailOptions);
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
            const collegeAssignmentsResponse = await docClient.send(new ScanCommand({
                TableName: "TestifyAssignments",
                FilterExpression: "college = :c",
                ExpressionAttributeValues: { ":c": studentCollege }
            }));
            const collegeAssignedTestIds = collegeAssignmentsResponse.Items.map(a => a.testId);

            const individualAssignmentsResponse = await docClient.send(new ScanCommand({
                TableName: "TestifyAssignments",
                FilterExpression: "studentEmail = :email",
                ExpressionAttributeValues: { ":email": studentEmail }
            }));
            const individualAssignedTestIds = individualAssignmentsResponse.Items.map(a => a.testId);

            const assignedTestIds = [...new Set([...collegeAssignedTestIds, ...individualAssignedTestIds])];

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

        res.json({
            stats: { overallScore, testsCompleted, passRate },
            newTests: availableTests,
            recentHistory
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
    
    const { testId, answers, timeTaken, violationReason } = req.body;
    const studentEmail = req.user.email;
    const resultId = uuidv4();

    try {
        const { Item: test } = await docClient.send(new GetCommand({
            TableName: "TestifyTests",
            Key: { testId }
        }));

        if (!test) return res.status(404).json({ message: "Test not found." });

        let score = 0;
        test.questions.forEach((question, index) => {
            const studentAnswer = answers[index];
            if (studentAnswer === null || studentAnswer === undefined) return;

            if (question.type === 'mcq-single' || question.type === 'fill-blank') {
                if (String(studentAnswer).trim().toLowerCase() === String(question.correctAnswer).trim().toLowerCase()) {
                    score += parseInt(question.marks, 10);
                }
            } else if (question.type === 'mcq-multiple') {
                const correctAnswers = new Set(question.correctAnswers);
                const studentAnswersSet = new Set(studentAnswer);
                if (correctAnswers.size === studentAnswersSet.size && [...correctAnswers].every(val => studentAnswersSet.has(val))) {
                     score += parseInt(question.marks, 10);
                }
            }
        });

        const percentageScore = Math.round((score / test.totalMarks) * 100);
        const result = percentageScore >= test.passingPercentage ? "Pass" : "Fail";

        const newResult = {
            resultId,
            testId,
            studentEmail,
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

        const testIds = [...new Set(results.map(r => r.testId))];
        if (testIds.length === 0) {
            return res.json([]);
        }
        
        const keys = testIds.map(testId => ({ testId }));

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
        const testMap = new Map(tests.map(t => [t.testId, t]));

        const enrichedHistory = results.map(result => {
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
                html: `
                    <div style="font-family: Arial, sans-serif; border: 5px solid #4F46E5; padding: 20px; text-align: center;">
                        <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1756037774/Gemini_Generated_Image_eu0ib0eu0ib0eu0i_z0amjh.png" alt="TESTIFY Logo" style="width: 80px; margin-bottom: 20px;">
                        <h1 style="color: #4F46E5;">Certificate of Achievement</h1>
                        <p style="font-size: 18px;">This is to certify that</p>
                        <h2 style="font-size: 24px; color: #111827; margin: 10px 0;">${studentName}</h2>
                        <p style="font-size: 18px;">has successfully completed the test</p>
                        <h3 style="font-size: 22px; color: #111827; margin: 10px 0;">${testTitle}</h3>
                        <p style="font-size: 16px;">on ${issueDate}</p>
                    </div>
                `
            };
            await transporter.sendMail(mailOptions);
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
            TableName: "TestifyCertificates",
            Key: { certificateId: id }
        }));

        if (!certificate || certificate.studentEmail !== studentEmail) {
            return res.status(404).json({ message: "Certificate not found or access denied." });
        }

        const { Item: student } = await docClient.send(new GetCommand({
            TableName: "TestifyUsers",
            Key: { email: studentEmail }
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
            issuedAt: certificate.issuedAt
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

    if (!language || !code) {
        return res.status(400).json({ message: 'Language and code are required.' });
    }

    // Map your language names to Judge0 language IDs
    // Find more here: https://judge0.com/
    const languageMap = {
        'c': 50,      // GCC 9.2.0
        'cpp': 54,    // GCC 9.2.0
        'java': 62,   // OpenJDK 13.0.1
        'python': 71, // Python 3.8.1
    };

    const languageId = languageMap[language];
    if (!languageId) {
        return res.status(400).json({ message: `Language '${language}' is not supported.` });
    }

    try {
        const submissionPayload = {
            language_id: languageId,
            source_code: Buffer.from(code).toString('base64'),
            stdin: Buffer.from(input || "").toString('base64'),
            encode_base64: true
        };

        const submissionResponse = await fetch('https://judge0-ce.p.rapidapi.com/submissions?base64_encoded=true&wait=true', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-RapidAPI-Key': 'YOUR_RAPIDAPI_KEY', // IMPORTANT: Replace with your actual RapidAPI key for Judge0
                'X-RapidAPI-Host': 'judge0-ce.p.rapidapi.com'
            },
            body: JSON.stringify(submissionPayload)
        });

        if (!submissionResponse.ok) {
            const errorBody = await submissionResponse.text();
            console.error("Judge0 API Error:", errorBody);
            return res.status(500).json({ message: 'Error communicating with the compilation service.' });
        }

        const result = await submissionResponse.json();

        // Decode the output from base64
        let output = '';
        if (result.stdout) {
            output = Buffer.from(result.stdout, 'base64').toString('utf-8');
        }
        
        // Handle different kinds of errors
        if (result.stderr) {
            output += `\nError:\n${Buffer.from(result.stderr, 'base64').toString('utf-8')}`;
        }
        if (result.compile_output) {
             output += `\nCompilation Error:\n${Buffer.from(result.compile_output, 'base64').toString('utf-8')}`;
        }
        if(result.status.description === 'Time Limit Exceeded'){
             output = 'Error: Time Limit Exceeded. Your code took too long to run.';
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
            html: `<p>You have requested a password reset for your TESTIFY account.</p>
                   <p>Click <a href="${resetLink}">here</a> to reset your password.</p>
                   <p>If you did not request this, please ignore this email.</p>`
        };

        await transporter.sendMail(mailOptions);
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
    
    const { problemId, problemTitle, difficulty, score } = req.body;
    const studentEmail = req.user.email;

    if (!problemId || !problemTitle || !difficulty || score === undefined) {
        return res.status(400).json({ message: 'Missing required score data.' });
    }
    
    // To prevent duplicate score submissions for the same problem
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
            return res.status(409).json({ message: 'Score for this problem has already been submitted.' });
        }

        const scoreId = uuidv4();
        const newScore = {
            scoreId,
            studentEmail,
            problemId,
            problemTitle,
            difficulty,
            score,
            submittedAt: new Date().toISOString()
        };

        await docClient.send(new PutCommand({
            TableName: "TestifyCompilerScores",
            Item: newScore
        }));

        res.status(201).json({ message: 'Score saved successfully!' });

    } catch (error) {
        console.error("Save Compiler Score Error:", error);
        res.status(500).json({ message: 'Server error saving score.' });
    }
});


// GET endpoint for admins/moderators to view all compiler scores
app.get('/api/admin/compiler-scores', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    try {
        const { Items: scores } = await docClient.send(new ScanCommand({
            TableName: "TestifyCompilerScores"
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

        const enrichedScores = scores.map(score => {
            const studentInfo = studentMap.get(score.studentEmail);
            return {
                ...score,
                studentName: studentInfo ? studentInfo.fullName : 'Unknown',
                college: studentInfo ? studentInfo.college : 'Unknown'
            };
        });
        
        // Sort by submission date, newest first
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


// --- SERVER START ---
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
