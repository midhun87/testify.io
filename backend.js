// backend.js
// --- IMPORTS ---
const express = require('express');
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, PutCommand, GetCommand, ScanCommand, QueryCommand, UpdateCommand, BatchGetCommand, DeleteCommand } = require("@aws-sdk/lib-dynamodb");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

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
    if (!token) return res.status(401).json({ message: 'No token, authorization denied' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (e) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

// =================================================================
// --- ROOT ROUTE ---
// =================================================================
app.get('/', (req, res) => res.redirect('/welcome.html'));

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
// --- COLLEGE MANAGEMENT ROUTES ---
// =================================================================
app.post('/api/colleges', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    const { collegeName } = req.body;
    if (!collegeName) return res.status(400).json({ message: 'College name is required.' });
    const newCollege = { collegeName };
    try {
        await docClient.send(new PutCommand({
            TableName: "TestifyColleges",
            Item: newCollege,
            ConditionExpression: "attribute_not_exists(collegeName)"
        }));
        res.status(201).json({ message: 'College added successfully!', college: newCollege });
    } catch (error) {
        if (error.name === 'ConditionalCheckFailedException') {
            return res.status(400).json({ message: 'College with this name already exists.' });
        }
        console.error("Add College Error:", error);
        res.status(500).json({ message: 'Server error adding college.' });
    }
});

app.get('/api/colleges', async (req, res) => {
    try {
        const { Items } = await docClient.send(new ScanCommand({ TableName: "TestifyColleges" }));
        Items.sort((a, b) => a.collegeName.localeCompare(b.collegeName));
        res.json(Items);
    } catch (error) {
        console.error("Get Colleges Error:", error);
        res.status(500).json({ message: 'Server error fetching colleges.' });
    }
});

app.delete('/api/colleges/:collegeName', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    const { collegeName } = req.params;
    try {
        await docClient.send(new DeleteCommand({
            TableName: "TestifyColleges",
            Key: { collegeName }
        }));
        res.status(200).json({ message: 'College deleted successfully.' });
    } catch (error) {
        console.error("Delete College Error:", error);
        res.status(500).json({ message: 'Server error deleting college.' });
    }
});

// =================================================================
// --- ADMIN ROUTES ---
// =================================================================

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
        const collegeData = { labels: Object.keys(collegeCounts), counts: Object.values(collegeCounts) };
        const testPerformance = tests.map(test => {
            const relevantResults = results.filter(r => r.testId === test.testId);
            const totalScore = relevantResults.reduce((sum, r) => sum + r.score, 0);
            return { title: test.title, avgScore: relevantResults.length > 0 ? Math.round(totalScore / relevantResults.length) : 0 };
        });
        const performanceData = { labels: testPerformance.map(t => t.title), scores: testPerformance.map(t => t.avgScore) };
        const studentMap = new Map(students.map(s => [s.email, s.fullName]));
        const testMap = new Map(tests.map(t => [t.testId, t.title]));
        const recentSubmissions = results
            .sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt))
            .slice(0, 5)
            .map(r => ({ ...r, studentName: studentMap.get(r.studentEmail) || 'Unknown', testTitle: testMap.get(r.testId) || 'Unknown' }));
        res.json({ stats: { totalTests, totalStudents, totalAttempts, avgPassRate }, collegeData, performanceData, recentSubmissions });
    } catch (error) {
        console.error("Get Admin Dashboard Error:", error);
        res.status(500).json({ message: 'Server error fetching dashboard data.' });
    }
});

app.post('/api/tests', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    const { testTitle, duration, totalMarks, passingPercentage, questions } = req.body;
    const testId = uuidv4();
    const newTest = { testId, title: testTitle, duration, totalMarks, passingPercentage, questions, createdAt: new Date().toISOString(), status: 'Not Assigned', resultsPublished: false };
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
    const { testId, testName, colleges, sendEmail } = req.body;
    try {
        for (const college of colleges) {
            const assignmentId = uuidv4();
            const assignment = { assignmentId, testId, college, assignedAt: new Date().toISOString() };
            await docClient.send(new PutCommand({ TableName: "TestifyAssignments", Item: assignment }));
        }
        await docClient.send(new UpdateCommand({
            TableName: "TestifyTests",
            Key: { testId },
            UpdateExpression: "set #status = :status",
            ExpressionAttributeNames: { "#status": "status" },
            ExpressionAttributeValues: { ":status": `Assigned to ${colleges.length} college(s)` }
        }));
        if (sendEmail && colleges.length > 0) {
            const filterExpression = colleges.map((_, index) => `college = :c${index}`).join(' OR ');
            const expressionAttributeValues = {};
            colleges.forEach((college, index) => { expressionAttributeValues[`:c${index}`] = college; });
            const { Items: students } = await docClient.send(new ScanCommand({ TableName: "TestifyUsers", FilterExpression: filterExpression, ExpressionAttributeValues: expressionAttributeValues }));
            const studentEmails = students.map(s => s.email);
            if (studentEmails.length > 0) {
                const mailOptions = { from: '"TESTIFY" <craids22@gmail.com>', to: studentEmails.join(','), subject: `New Test Assigned: ${testName}`, html: `<p>Hello,</p><p>A new test, "<b>${testName}</b>", has been assigned to you. Please log in to your TESTIFY dashboard to take the test.</p><p>Best regards,<br/>The TESTIFY Team</p>` };
                await transporter.sendMail(mailOptions);
            }
        }
        res.status(200).json({ message: 'Test assigned successfully!' });
    } catch (error) {
        console.error("Assign Test Error:", error);
        res.status(500).json({ message: 'Server error assigning test.' });
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
            return { testId: test.testId, title: test.title, attempted: relevantResults.length, passed: passedCount, failed: failedCount, resultsPublished: test.resultsPublished || false };
        });
        res.json(history);
    } catch (error) {
        console.error("Get Admin History Error:", error);
        res.status(500).json({ message: 'Server error fetching history.' });
    }
});

app.post('/api/publish-results', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    const { testId } = req.body;
    try {
        await docClient.send(new UpdateCommand({
            TableName: "TestifyTests",
            Key: { testId },
            UpdateExpression: "set resultsPublished = :true",
            ExpressionAttributeValues: { ":true": true }
        }));
        res.status(200).json({ message: 'Results published successfully!' });
    } catch (error) {
        console.error("Publish Results Error:", error);
        res.status(500).json({ message: 'Server error publishing results.' });
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
        const { Item: existingTest } = await docClient.send(new GetCommand({ TableName: "TestifyTests", Key: { testId } }));
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
        await docClient.send(new PutCommand({ TableName: "TestifyTests", Item: updatedTest }));
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
        const { Item: test } = await docClient.send(new GetCommand({ TableName: "TestifyTests", Key: { testId } }));
        if (!test) return res.status(404).json({ message: "Test not found." });
        const { Items: results } = await docClient.send(new ScanCommand({ TableName: "TestifyResults", FilterExpression: "testId = :tid", ExpressionAttributeValues: { ":tid": testId } }));
        const { Items: students } = await docClient.send(new ScanCommand({ TableName: "TestifyUsers", FilterExpression: "#role = :student", ExpressionAttributeNames: {"#role": "role"}, ExpressionAttributeValues: {":student": "Student"} }));
        const studentMap = new Map(students.map(s => [s.email, { name: s.fullName, college: s.college }]));
        const reportResults = results.map(result => {
            const studentInfo = studentMap.get(result.studentEmail) || { name: 'Unknown', college: 'Unknown' };
            return { ...result, studentName: studentInfo.name, college: studentInfo.college };
        });
        res.json({ testTitle: test.title, results: reportResults });
    } catch (error) {
        console.error("Get Test Report Error:", error);
        res.status(500).json({ message: 'Server error fetching report data.' });
    }
});

// =================================================================
// --- STUDENT ROUTES ---
// =================================================================

app.get('/api/student/tests', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    try {
        const studentCollege = req.user.college;
        if (!studentCollege) return res.json([]);
        const assignmentsResponse = await docClient.send(new ScanCommand({ TableName: "TestifyAssignments", FilterExpression: "college = :c", ExpressionAttributeValues: { ":c": studentCollege } }));
        const assignedTestIds = assignmentsResponse.Items.map(a => a.testId);
        if (assignedTestIds.length === 0) return res.json([]);
        const resultsResponse = await docClient.send(new QueryCommand({ TableName: "TestifyResults", IndexName: "StudentEmailIndex", KeyConditionExpression: "studentEmail = :email", ExpressionAttributeValues: { ":email": req.user.email } }));
        const completedTestIds = resultsResponse.Items.map(r => r.testId);
        const availableTestIds = assignedTestIds.filter(id => !completedTestIds.includes(id));
        if (availableTestIds.length === 0) return res.json([]);
        const uniqueTestIds = [...new Set(availableTestIds)];
        const keys = uniqueTestIds.map(testId => ({ testId }));
        const testsResponse = await docClient.send(new BatchGetCommand({ RequestItems: { "TestifyTests": { Keys: keys } } }));
        res.json(testsResponse.Responses.TestifyTests || []);
    } catch (error) {
        console.error("Get Student Tests Error:", error);
        res.status(500).json({ message: 'Server error fetching student tests.' });
    }
});

app.post('/api/student/submit-test', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    const { testId, answers, timeTaken } = req.body;
    const resultId = uuidv4();
    try {
        const { Item: test } = await docClient.send(new GetCommand({ TableName: "TestifyTests", Key: { testId } }));
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
        const newResult = { resultId, testId, studentEmail: req.user.email, answers, timeTaken, score: percentageScore, result, submittedAt: new Date().toISOString() };
        await docClient.send(new PutCommand({ TableName: "TestifyResults", Item: newResult }));
        res.status(201).json({ message: 'Test submitted successfully!' });
    } catch (error) {
        console.error("Submit Test Error:", error);
        res.status(500).json({ message: 'Server error submitting test.' });
    }
});

app.get('/api/student/history', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') return res.status(403).json({ message: 'Access denied.' });
    try {
        const { Items: results } = await docClient.send(new QueryCommand({ TableName: "TestifyResults", IndexName: "StudentEmailIndex", KeyConditionExpression: "studentEmail = :email", ExpressionAttributeValues: { ":email": req.user.email } }));
        if (!results || results.length === 0) return res.json([]);
        const testIds = [...new Set(results.map(r => r.testId))];
        if (testIds.length === 0) return res.json(results);
        const keys = testIds.map(testId => ({ testId }));
        const { Responses } = await docClient.send(new BatchGetCommand({
            RequestItems: { 
                "TestifyTests": { 
                    Keys: keys,
                    ProjectionExpression: "testId, title, #dur",
                    ExpressionAttributeNames: { "#dur": "duration" }
                } 
            }
        }));
        const tests = Responses.TestifyTests || [];
        const testMap = new Map(tests.map(t => [t.testId, t]));
        const enrichedHistory = results.map(result => {
            const testDetails = testMap.get(result.testId);
            return { ...result, testTitle: testDetails ? testDetails.title : "Unknown Test (ID not found)", testDuration: testDetails ? testDetails.duration : "N/A" };
        });
        res.json(enrichedHistory);
    } catch (error) {
        console.error("Get Student History Error:", error);
        res.status(500).json({ message: 'Server error fetching history.' });
    }
});

// --- SERVER START ---
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
