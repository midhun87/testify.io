// backend.js
// --- IMPORTS ---
const express = require('express');
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, PutCommand, GetCommand, ScanCommand, QueryCommand, UpdateCommand, BatchGetCommand } = require("@aws-sdk/lib-dynamodb");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const multer = require('multer');
const pdf = require('pdf-parse'); 
const fetch = require('node-fetch');

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

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// --- AUTHENTICATION MIDDLEWARE ---
const authMiddleware = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (e) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

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
            role: "Student"
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
        const isMatch = await bcrypt.compare(password, Item.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials.' });
        const payload = { user: { email: Item.email, fullName: Item.fullName, role: Item.role, college: Item.college } };
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
// --- ADMIN ROUTES (TESTS) ---
// =================================================================

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
        resultsPublished: false, // Default to false
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

app.get('/api/tests', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    try {
        const { Items } = await docClient.send(new ScanCommand({ TableName: "TestifyTests" }));
        res.json(Items);
    } catch (error) {
        console.error("Get Tests Error:", error);
        res.status(500).json({ message: 'Server error fetching tests.' });
    }
});

app.post('/api/assign-test', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });

    const { testId, testName, colleges, sendEmail, autoIssueCertificates } = req.body;

    try {
        for (const college of colleges) {
            const assignmentId = uuidv4();
            const assignment = {
                assignmentId,
                testId,
                college,
                assignedAt: new Date().toISOString()
            };
            await docClient.send(new PutCommand({ TableName: "TestifyAssignments", Item: assignment }));
        }

        await docClient.send(new UpdateCommand({
            TableName: "TestifyTests",
            Key: { testId },
            UpdateExpression: "set #status = :status, #autoIssue = :autoIssue",
            ExpressionAttributeNames: { 
                "#status": "status",
                "#autoIssue": "autoIssueCertificates"
            },
            ExpressionAttributeValues: { 
                ":status": `Assigned to ${colleges.length} college(s)`,
                ":autoIssue": autoIssueCertificates 
            }
        }));

        if (sendEmail && colleges.length > 0) {
            const filterExpression = colleges.map((_, index) => `college = :c${index}`).join(' OR ');
            const expressionAttributeValues = {};
            colleges.forEach((college, index) => {
                expressionAttributeValues[`:c${index}`] = college;
            });

            const { Items: students } = await docClient.send(new ScanCommand({
                TableName: "TestifyUsers",
                FilterExpression: filterExpression,
                ExpressionAttributeValues: expressionAttributeValues
            }));
            
            const studentEmails = students.map(s => s.email);
            if (studentEmails.length > 0) {
                const mailOptions = {
                    from: '"TESTIFY" <craids22@gmail.com>',
                    to: studentEmails.join(','),
                    subject: `New Test Assigned: ${testName}`,
                    html: `<p>Hello,</p><p>A new test, "<b>${testName}</b>", has been assigned to you. Please log in to your TESTIFY dashboard to take the test.</p><p>Best regards,<br/>The TESTIFY Team</p>`
                };
                await transporter.sendMail(mailOptions);
            }
        }
        res.status(200).json({ message: 'Test assigned successfully!' });
    } catch (error) {
        console.error("Assign Test Error:", error);
        res.status(500).json({ message: 'Server error assigning test.' });
    }
});

// =================================================================
// --- NEW: PUBLISH RESULTS ROUTE (ADMIN) ---
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


app.get('/api/admin/test-history', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    try {
        const { Items: tests } = await docClient.send(new ScanCommand({ TableName: "TestifyTests" }));
        const { Items: results } = await docClient.send(new ScanCommand({ TableName: "TestifyResults" }));

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
        console.error("Get Admin History Error:", error);
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
// --- COURSE MANAGEMENT ROUTES (ADMIN) ---
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

app.get('/api/admin/courses', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
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

app.post('/api/admin/assign-course', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });

    const { courseId, colleges, sendEmail } = req.body;

    try {
        const { Item: course } = await docClient.send(new GetCommand({ TableName: "TestifyCourses", Key: { courseId } }));
        if (!course) {
            return res.status(404).json({ message: "Course not found." });
        }

        const filterExpression = colleges.map((_, index) => `college = :c${index}`).join(' OR ');
        const expressionAttributeValues = {};
        colleges.forEach((college, index) => {
            expressionAttributeValues[`:c${index}`] = college;
        });

        const { Items: students } = await docClient.send(new ScanCommand({
            TableName: "TestifyUsers",
            FilterExpression: filterExpression,
            ExpressionAttributeValues: expressionAttributeValues
        }));

        if (students.length === 0) {
            return res.status(400).json({ message: "No students found in the selected colleges." });
        }

        for (const student of students) {
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
            const studentEmails = students.map(s => s.email);
            const mailOptions = {
                from: '"TESTIFY" <craids22@gmail.com>',
                to: studentEmails.join(','),
                subject: `New Course Assigned: ${course.title}`,
                html: `<p>Hello,</p><p>A new course, "<b>${course.title}</b>", has been assigned to you. Please log in to your TESTIFY dashboard to begin learning.</p><p>Best regards,<br/>The TESTIFY Team</p>`
            };
            await transporter.sendMail(mailOptions);
        }

        res.status(200).json({ message: `Course assigned to ${students.length} students successfully!` });
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

        // 1. Get all of the student's results
        const historyResponse = await docClient.send(new QueryCommand({
            TableName: "TestifyResults",
            IndexName: "StudentEmailIndex",
            KeyConditionExpression: "studentEmail = :email",
            ExpressionAttributeValues: { ":email": studentEmail }
        }));
        const allHistory = historyResponse.Items || [];

        // 2. Get details for all tests the student has ever taken
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

        // 3. Filter the history to only include results from PUBLISHED tests
        const history = allHistory.filter(r => {
            const testDetails = allTestsMap.get(r.testId);
            return testDetails && testDetails.resultsPublished === true;
        });

        // 4. Get available tests (assigned but not yet taken)
        let availableTests = [];
        if (studentCollege) {
            // --- FIX: Fetch college-wide and individual assignments separately for robustness ---
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

        // 5. Calculate stats based on the filtered (published) history
        const testsCompleted = history.length;
        const totalScore = history.reduce((sum, item) => sum + item.score, 0);
        const overallScore = testsCompleted > 0 ? Math.round(totalScore / testsCompleted) : 0;
        const passedCount = history.filter(item => item.result === 'Pass').length;
        const passRate = testsCompleted > 0 ? Math.round((passedCount / testsCompleted) * 100) : 0;
        
        // 6. Create recent history list from the filtered (published) history
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
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    
    try {
        const studentCollege = req.user.college;
        const studentEmail = req.user.email;
        if (!studentCollege) return res.json([]);

        // --- FIX: Fetch college-wide and individual assignments separately for robustness ---
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

        if (assignedTestIds.length === 0) return res.json([]);

        const resultsResponse = await docClient.send(new QueryCommand({
            TableName: "TestifyResults",
            IndexName: "StudentEmailIndex",
            KeyConditionExpression: "studentEmail = :email",
            ExpressionAttributeValues: { ":email": req.user.email }
        }));
        const completedTestIds = resultsResponse.Items.map(r => r.testId);

        const availableTestIds = assignedTestIds.filter(id => !completedTestIds.includes(id));
        if (availableTestIds.length === 0) return res.json([]);

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
    
    const { testId, answers, timeTaken } = req.body;
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
            submittedAt: new Date().toISOString()
        };
    
        await docClient.send(new PutCommand({ TableName: "TestifyResults", Item: newResult }));

        if (result === "Pass" && test.autoIssueCertificates === true) {
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

app.get('/api/admin/test-report/:testId', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    
    const { testId } = req.params;

    try {
        const { Item: test } = await docClient.send(new GetCommand({
            TableName: "TestifyTests",
            Key: { testId }
        }));

        if (!test) {
            return res.status(404).json({ message: "Test not found." });
        }

        const { Items: results } = await docClient.send(new ScanCommand({
            TableName: "TestifyResults",
            FilterExpression: "testId = :tid",
            ExpressionAttributeValues: { ":tid": testId }
        }));

        const { Items: students } = await docClient.send(new ScanCommand({
            TableName: "TestifyUsers",
            FilterExpression: "#role = :student",
            ExpressionAttributeNames: {"#role": "role"},
            ExpressionAttributeValues: {":student": "Student"}
        }));
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
            studentName: student ? student.fullName : 'Student'
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

// --- SERVER START ---
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

