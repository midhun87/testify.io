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
        user: 'craids22@gmail.com',
        pass: 'opok nwqf kukx aihh'
    }
});

// --- CLOUDINARY CONFIG ---
cloudinary.config({
  cloud_name: 'dpz44zf0z',
  api_key: '939929349547989',
  api_secret: '7mwxyaqe-tvtilgyek2oR7lTkr8'
});
const upload = multer({ storage: multer.memoryStorage() });

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));
// --- NEW LINE ADDED ---
// This makes sure that files inside the 'moderator' folder are also served correctly.
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

        // Add assignedColleges to the request object if the user is a Moderator
        if (Item.role === 'Moderator') {
            req.user.assignedColleges = Item.assignedColleges || [];
        }


        next();
    } catch (e) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};


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
            assignedColleges, // Array of college names
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
        res.json(Items.map(({ password, ...rest }) => rest)); // Exclude password from response
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
        // Sort colleges alphabetically for consistent display
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
        // Check if college already exists to prevent duplicates
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
            from: '"TESTIFY" <craids22@gmail.com>',
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
    const { fullName, email, mobile, college, department, rollNumber, password } = req.body;
    if (!fullName || !email || !mobile || !college || !department || !rollNumber || !password) {
        return res.status(400).json({ message: 'Please fill all fields.' });
    }
    try {
        const existingUser = await docClient.send(new GetCommand({ TableName: "TestifyUsers", Key: { email: email.toLowerCase() } }));
        if (existingUser.Item) {
            return res.status(400).json({ message: 'User with this email already exists.' });
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = {
            email: email.toLowerCase(),
            fullName,
            mobile,
            college,
            department,
            rollNumber,
            password: hashedPassword,
            role: "Student",
            isBlocked: false
        };
        await docClient.send(new PutCommand({ TableName: "TestifyUsers", Item: newUser }));
        res.status(201).json({ message: 'Account created successfully!' });
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
                college: Item.college, // For students
                assignedColleges: Item.assignedColleges, // For moderators
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

// This middleware checks if the user is an Admin or a Moderator
const adminOrModeratorAuth = (req, res, next) => {
    if (req.user.role !== 'Admin' && req.user.role !== 'Moderator') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    next();
};

app.post('/api/tests', authMiddleware, async (req, res) => {
    // Only Admins can create tests from scratch
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
    // Both Admin and Moderator can see the list of available tests
    try {
        const { Items } = await docClient.send(new ScanCommand({ TableName: "TestifyTests" }));
        res.json(Items);
    } catch (error) {
        console.error("Get Tests Error:", error);
        res.status(500).json({ message: 'Server error fetching tests.' });
    }
});

// In backend.js, replace the '/api/assign-test' route
app.post('/api/assign-test', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    const { testId, testName, colleges, studentEmails, sendEmail, autoIssueCertificates } = req.body;

    try {
        let studentsToNotify = [];

        // Prioritize individual student assignment
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
        // Fallback to college-based assignment
        else if (colleges && colleges.length > 0) {
            if (req.user.role === 'Moderator') {
                const isAllowed = colleges.every(college => req.user.assignedColleges.includes(college));
                if (!isAllowed) {
                    return res.status(403).json({ message: 'You can only assign tests to your assigned colleges.' });
                }
            }
            for (const college of colleges) {
                const assignmentId = uuidv4();
                await docClient.send(new PutCommand({
                    TableName: "TestifyAssignments",
                    Item: { assignmentId, testId, college, assignedAt: new Date().toISOString() }
                }));
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
                from: '"TESTIFY" <craids22@gmail.com>',
                to: studentsToNotify.join(','),
                subject: `New Test Assigned: ${testName}`,
                html: `<p>Hello,</p><p>A new test, "<b>${testName}</b>", has been assigned to you. Please log in to your TESTIFY dashboard to take the test.</p><p>Best regards,<br/>The TESTIFY Team</p>`
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

        // If moderator, filter results by their colleges
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

// In backend.js, replace the '/api/admin/assign-course' route
app.post('/api/admin/assign-course', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    const { courseId, colleges, studentEmails, sendEmail } = req.body;
    let studentsToAssign = [];

    try {
        const { Item: course } = await docClient.send(new GetCommand({ TableName: "TestifyCourses", Key: { courseId } }));
        if (!course) {
            return res.status(404).json({ message: "Course not found." });
        }

        // Prioritize individual student assignment
        if (studentEmails && studentEmails.length > 0) {
            const keys = studentEmails.map(email => ({ email }));
            const { Responses } = await docClient.send(new BatchGetCommand({
                RequestItems: { "TestifyUsers": { Keys: keys } }
            }));
            studentsToAssign = Responses.TestifyUsers || [];
        } 
        // Fallback to college-based assignment
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
                from: '"TESTIFY" <craids22@gmail.com>',
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
                    from: '"TESTIFY" <craids22@gmail.com>',
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

// In backend.js, replace the '/api/student/tests' route

app.get('/api/student/tests', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    
    try {
        const studentCollege = req.user.college;
        const studentEmail = req.user.email;
        if (!studentCollege) return res.json([]);

        // Get all assignments for the student (both individual and by college)
        const collegeAssignmentsResponse = await docClient.send(new ScanCommand({
            TableName: "TestifyAssignments",
            FilterExpression: "college = :c",
            ExpressionAttributeValues: { ":c": studentCollege }
        }));
        const individualAssignmentsResponse = await docClient.send(new ScanCommand({
            TableName: "TestifyAssignments",
            FilterExpression: "studentEmail = :email",
            ExpressionAttributeValues: { ":email": studentEmail }
        }));
        
        const allAssignments = [
            ...collegeAssignmentsResponse.Items, 
            ...individualAssignmentsResponse.Items
        ];

        if (allAssignments.length === 0) return res.json([]);

        // Get all results submitted by the student
        const resultsResponse = await docClient.send(new QueryCommand({
            TableName: "TestifyResults",
            IndexName: "StudentEmailIndex",
            KeyConditionExpression: "studentEmail = :email",
            ExpressionAttributeValues: { ":email": studentEmail }
        }));
        const studentResults = resultsResponse.Items;

        // LOGIC CHANGE: Determine which tests are truly available
        const availableTestIds = [];
        const assignmentCounts = {};
        const resultCounts = {};

        // Count how many times each test was assigned
        for (const assignment of allAssignments) {
            assignmentCounts[assignment.testId] = (assignmentCounts[assignment.testId] || 0) + 1;
        }

        // Count how many times the student submitted results for each test
        for (const result of studentResults) {
            resultCounts[result.testId] = (resultCounts[result.testId] || 0) + 1;
        }

        // A test is available if it has been assigned more times than it has been attempted
        for (const testId in assignmentCounts) {
            const assignedCount = assignmentCounts[testId];
            const attemptedCount = resultCounts[testId] || 0;
            if (assignedCount > attemptedCount) {
                availableTestIds.push(testId);
            }
        }

        if (availableTestIds.length === 0) return res.json([]);

        // Fetch the details for the available tests
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
// --- In backend.js, replace your existing '/api/student/submit-test' route ---

app.post('/api/student/submit-test', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    
    // Destructure the new 'violationReason' field from the request body
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
            // Add the violation reason to the result object. If it's undefined, it won't be saved.
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
        console.error("Update Test Error:", error);
        res.status(500).json({ message: 'Server error updating test.' });
    }
});

// --- In backend.js, find and replace this entire route ---

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
        // Moderator can only see reports for their colleges
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
                from: '"TESTIFY" <craids22@gmail.com>',
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

// Get students by college (for Admin) or assigned colleges (for Moderator)
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

        // This part can be optimized if performance becomes an issue
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


// Update student details
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

// Admin or Moderator can change a student's profile image
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


// Delete a student (Admin only)
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

// Block/Unblock a student
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

//face verification

// Add this with your other imports at the top of backend.js
const { RekognitionClient, CompareFacesCommand } = require("@aws-sdk/client-rekognition");

// Add this with your other client setups
const rekognitionClient = new RekognitionClient({
    region: 'ap-south-1', // Or your preferred AWS region
    credentials: {
        accessKeyId: 'AKIAVEP3EDM5MKMROQRB', // It's better to use environment variables for these
        secretAccessKey: 'cvELln8Bg4cmGv7Uhwcd1KWdxW14ulZbVf8Xo+gr'
    }
});

// --- Make sure 'fetch' is available at the top of your file ---
// You already have this line, but just confirming:
// const fetch = require('node-fetch');

// --- REPLACE the existing face-verification route with this one ---
// In backend.js, find and replace this entire route

app.post('/api/student/face-verification', authMiddleware, async (req, res) => {
    const { profileImageUrl, webcamImage } = req.body;

    if (!profileImageUrl || !webcamImage) {
        return res.status(400).json({ message: 'Missing required image data.' });
    }

    try {
        // --- Step 1: Fetch profile image from Cloudinary ---
        const profileImageResponse = await fetch(profileImageUrl);
        if (!profileImageResponse.ok) {
            // This will now throw a specific error if Cloudinary fails
            throw new Error('Failed to download profile image from Cloudinary.');
        }
        const profileImageBuffer = await profileImageResponse.buffer();

        // --- Step 2: Prepare webcam image ---
        const webcamImageBuffer = Buffer.from(webcamImage.replace(/^data:image\/jpeg;base64,/, ""), 'base64');

        // --- Step 3: Call AWS Rekognition ---
        const command = new CompareFacesCommand({
            SourceImage: { Bytes: profileImageBuffer },
            TargetImage: { Bytes: webcamImageBuffer },
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
        // --- MODIFIED & IMPROVED ERROR HANDLING ---
        console.error('Face Verification Error:', error); // Detailed log for you on Render
        
        let userMessage = 'An error occurred during face verification.';
        
        // Provide more specific feedback to the frontend
        if (error.name === 'AccessDeniedException') {
            userMessage = 'AWS Rekognition service access denied. Please check your IAM user permissions.';
        } else if (error.message.includes('Cloudinary')) {
            userMessage = 'Could not retrieve profile image from the server.';
        } else if (error.name) {
            // Send back the specific AWS error name
            userMessage = `AWS Error: ${error.name}. Please check server logs.`;
        }
        
        res.status(500).json({ message: userMessage });
    }
});
// Get ALL students (for Admin) or all students in assigned colleges (for Moderator)
app.get('/api/admin/all-students', authMiddleware, adminOrModeratorAuth, async (req, res) => {
    try {
        let filterExpression = "#role = :student";
        let expressionAttributeValues = { ":student": "Student" };
        
        if (req.user.role === 'Moderator') {
            if (req.user.assignedColleges.length === 0) {
                return res.json([]); // Moderator with no colleges sees no students
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

        // Fetch all test results and course progresses to enrich student data
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

// =================================================================
// --- NEW: IMPACT STATS ROUTES ---
// =================================================================

// GET route for public "About Us" page (no auth needed)
// =================================================================
// --- IMPACT STATS & FLYER ROUTES (USING TestifyUsers TABLE) ---
// =================================================================

// GET route for public pages (no auth needed)
app.get('/api/impact-stats', async (req, res) => {
    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: "TestifyUsers",
            Key: { email: "_system_impact_stats" }
        }));
        
        if (Item) {
            // Return all stats, including the flyer image URL if it exists
            res.json({
                institutions: Item.institutions,
                exams: Item.exams,
                uptime: Item.uptime,
                flyerImageUrl: Item.flyerImageUrl || null
            });
        } else {
            // Return default values if nothing is saved yet
            res.json({ institutions: "0+", exams: "0+", uptime: "0%", flyerImageUrl: null });
        }
    } catch (error) {
        console.error("Get Impact Stats Error:", error);
        res.status(500).json({ message: 'Server error fetching stats.' });
    }
});

// POST route for admin to update stats and upload flyer (auth needed)
// Using upload.single() to handle the flyer image file
app.post('/api/admin/impact-stats', authMiddleware, upload.single('flyerImage'), async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    
    const { institutions, exams, uptime } = req.body;
    let flyerImageUrl;

    try {
        // First, fetch the existing record to see if there's an old image URL
        const { Item: existingStats } = await docClient.send(new GetCommand({
            TableName: "TestifyUsers",
            Key: { email: "_system_impact_stats" }
        }));

        // If a new file is uploaded, send it to Cloudinary
        if (req.file) {
            const b64 = Buffer.from(req.file.buffer).toString("base64");
            const dataURI = "data:" + req.file.mimetype + ";base64," + b64;
            const result = await cloudinary.uploader.upload(dataURI, {
                folder: "flyers"
            });
            flyerImageUrl = result.secure_url;
        } else {
            // If no new file, keep the existing URL
            flyerImageUrl = existingStats ? existingStats.flyerImageUrl : null;
        }

        // Prepare the data for DynamoDB
        const statsData = {
            email: "_system_impact_stats",
            recordType: "ImpactStats",
            institutions,
            exams,
            uptime,
            flyerImageUrl // Add the new or existing image URL
        };

        // Use PutCommand to create or overwrite the item
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

app.post('/api/compile', authMiddleware, async (req, res) => {
    const { language, code, input } = req.body; // Added 'input'

    if (!language || !code) {
        return res.status(400).json({ message: 'Language and code are required.' });
    }

    try {
        const response = await fetch('https://api.paiza.io/runners/create', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                language: language,
                source_code: code,
                input: input || "", // Pass the input to the execution API
                api_key: 'guest'
            })
        });

        const data = await response.json();

        if (data.id) {
            // Wait a moment for the execution to start
            await new Promise(resolve => setTimeout(resolve, 2000));

            const statusResponse = await fetch(`https://api.paiza.io/runners/get_details?id=${data.id}&api_key=guest`);
            const statusData = await statusResponse.json();
            
            let output = '';
            if (statusData.stdout) {
                output += statusData.stdout;
            }
            if (statusData.stderr) {
                output += `\nError:\n${statusData.stderr}`;
            }
            if (statusData.build_stderr) {
                output += `\nBuild Error:\n${statusData.build_stderr}`;
            }
            
            res.json({ output: output || 'No output.' });

        } else {
            res.status(500).json({ message: 'Failed to create runner.' });
        }
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

// ADMIN: Get all practice tests
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

// ADMIN: Assign a practice test
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

// STUDENT: Get assigned practice tests
app.get('/api/student/practice-tests', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    
    try {
        // CORRECTED: Use req.user which is set by the authMiddleware
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

// STUDENT: Submit practice test (simplified)
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
            totalMarks += (question.marks || 1); // Assume 1 mark if not specified
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

        // We don't save practice test results, just return the score
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
// --- SERVER START ---
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

