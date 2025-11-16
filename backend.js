// backend_moderator.js
require('dotenv').config();
const express = require('express');
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, PutCommand, GetCommand, ScanCommand, QueryCommand, UpdateCommand, BatchGetCommand, DeleteCommand, BatchWriteCommand } = require("@aws-sdk/lib-dynamodb");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
// const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const multer = require('multer');
const pdf = require('pdf-parse');
const fetch = require('node-fetch');
const cloudinary = require('cloudinary').v2;
const { RekognitionClient, CompareFacesCommand } = require("@aws-sdk/client-rekognition");
const crypto = require('crypto');
const SibApiV3Sdk = require('sib-api-v3-sdk');
const { Server } = require("socket.io"); 
const http = require('http');
const router = express.Router();
const Razorpay = require('razorpay')
const stream = require('stream')
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const S3_BUCKET_NAME = "hirewithusjobapplications"; 
const AWS_S3_REGION = "ap-south-1"; 
const CORRECT_JOBS_TABLE_NAME = "TestifyJobs";
const HIRING_TRIAL_USERS_TABLE = "HiringTrialUsers";
const HIRING_USERS_TABLE = "HiringUsers";
const HIRING_COLLEGES_TABLE = "HiringColleges";
const HIRING_JOBS_TABLE = "HiringJobs";                 // Aptitude tests / Job postings
const HIRING_APPLICATIONS_TABLE = "HiringApplications"; // Applications for HIRING_JOBS_TABLE items
const HIRING_CODING_PROBLEMS_TABLE = "HiringCodingProblems";
const HIRING_CODING_TESTS_TABLE = "HiringCodingTests";
const HIRING_ASSIGNMENTS_TABLE = "HiringAssignments";   // Assignments for both HIRING_JOBS_TABLE and HIRING_CODING_TESTS_TABLE items
const HIRING_TEST_RESULTS_TABLE = "HiringTestResults";   // Results for both types of tests
const APPLICATIONS_TABLE = "HiringApplications"; // Use the correct table name
const JOBS_TABLE = "HiringJobs"; // Use the correct table name
const HIRING_CODE_SNIPPETS_TABLE = "HiringCodeSnippets"; // New table for saving snippets
const HIRING_APTITUDE_TESTS_TABLE = "HiringAptitudeTests";
const HIRING_INTERVIEWS_TABLE = "HiringInterviews"; // Table for interview slots, events, & evaluations
const APPLICATIONS_TABLE_NAME = "TestifyApplications";


const ZOOM_ACCOUNT_ID = process.env.ZOOM_ACCOUNT_ID || 'bq5-fIbESBONjaZAr184uA';
const ZOOM_CLIENT_ID = process.env.ZOOM_CLIENT_ID || 'CXxbks94RlmD_90vofVqg';
const ZOOM_CLIENT_SECRET = process.env.ZOOM_CLIENT_SECRET || 'XXoYPmG5z8rSf1J6Fov7iXSminmBRuO9';

// [ADD THESE]
const {
    KinesisVideoClient,
    CreateSignalingChannelCommand,
    GetSignalingChannelEndpointCommand,
    DeleteSignalingChannelCommand,
    DescribeSignalingChannelCommand
} = require("@aws-sdk/client-kinesis-video");

const {
    KinesisVideoSignalingClient,
    GetIceServerConfigCommand
} = require("@aws-sdk/client-kinesis-video-signaling");

// [ADD THIS]
// This is the client for creating/managing channels
const kinesisVideoClient = new KinesisVideoClient({
    region: process.env.AWS_REGION || "ap-south-1",
    credentials: {
        accessKeyId: 'AKIAT4YSUMZD52BNBCAB', // Your existing key
        secretAccessKey: process.env.CHIME_AWS_SECRET_ACCESS_KEY || 'jCJQY7lfiv1LylIqLpzFl9kz96r4FgLcKL+SueGh' // Your existing secret
    }
});

const liveTestSessions = {};

//Mails by SES

const { SESv2Client, SendEmailCommand } = require("@aws-sdk/client-sesv2");

const sesClient = new SESv2Client({
    region: process.env.AWS_REGION || 'ap-south-1',
    credentials: {
        accessKeyId: process.env.AWS_SES_ACCESS_KEY_ID || 'AKIAT4YSUMZD755UHGW7',
        secretAccessKey: process.env.AWS_SES_SECRET_ACCESS_KEY || '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'
    }
});

async function sendEmailWithSES(mailOptions) {
    // The 'to' field can be a string of comma-separated emails or an array. This handles both.
    const toAddresses = Array.isArray(mailOptions.to)
        ? mailOptions.to
        : mailOptions.to.split(',').map(e => e.trim());

    const params = {
        FromEmailAddress: '"TESTIFY" <support@testify-lac.com>',
        Destination: {
            ToAddresses: toAddresses,
        },
        Content: {
            Simple: {
                Subject: {
                    Data: mailOptions.subject,
                    Charset: 'UTF-8',
                },
                Body: {
                    Html: {
                        Data: mailOptions.html,
                        Charset: 'UTF-8',
                    },
                },
            },
        },
    };

    try {
        const command = new SendEmailCommand(params);
        const data = await sesClient.send(command);
        console.log('Email sent successfully with SES:', data.MessageId);
    } catch (error) {
        console.error('Error sending email with SES:', error);
    }
}

const s3Client = new S3Client({
    region: process.env.AWS_REGION || 'ap-south-1',
    credentials: {
        accessKeyId: 'AKIAT4YSUMZD755UHGW7', // Using same keys as DynamoDB/SES
        secretAccessKey: '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'
    }
});


const hiringModeratorAuth = async (req, res, next) => {
     await authMiddleware(req, res, () => {
        if (req.user && req.user.role === 'Hiring Moderator') {
            next();
        } else if (!res.headersSent) {
             res.status(403).json({ message: 'Access denied. Hiring Moderator role required.' });
        }
    });
};

const interviewerAuth = async (req, res, next) => {
    await authMiddleware(req, res, () => {
        if (req.user && req.user.role === 'Interviewer') {
            next();
        } else if (!res.headersSent) {
             res.status(403).json({ message: 'Access denied. Interviewer role required.' });
        }
    });
};

// --- INITIALIZATION ---
const app = express();
const server = http.createServer(app); // FIX: Create the HTTP server
const io = new Server(server, { cors: { origin: "*" } }); // FIX: Attach socket.io to the server
const PORT = 3000;
const JWT_SECRET = 'your-super-secret-key-for-jwt-in-production';




async function compileWithCustomCompiler(language, code, input) {
    // --- IMPORTANT: This is your custom compiler URL ---
    const compilerUrl = 'https://compiler-api-6k95.onrender.com';

    const languageMap = {
        'c': 'c',
        'cpp': 'cpp',
        'python': 'python',
        'javascript': 'javascript',
        'java': 'java' // Assuming your compiler supports java
    };

    const compilerLanguage = languageMap[language];

    if (!compilerLanguage) {
        throw new Error(`Language '${language}' is not supported by the custom compiler.`);
    }

    try {
        console.log(`[Custom Compiler] Sending request for ${language}. URL: ${compilerUrl}/api/compile`);
        // --- This fetch now uses the correct URL and body structure for your service ---
        const compileResponse = await fetch(`${compilerUrl}/api/compile`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                language: compilerLanguage,
                code: code,
                stdin: input || "" // Send input if provided
            })
        });

        const result = await compileResponse.json(); // Always try to parse JSON

        if (!compileResponse.ok) {
            console.error("[Custom Compiler] API Error:", compileResponse.status, result);
            // Try to extract a meaningful error message from your service's response
            const errorMessage = result?.message || result?.error || result?.stderr || `Execution failed (Status: ${compileResponse.status})`;
            throw new Error(`Compiler Service Error: ${errorMessage}`);
        }

        console.log(`[Custom Compiler] Success for ${language}. Status: ${result.status}`);

        // Combine stdout and stderr for the simple output field
        let output = result.stdout || '';
        if (result.stderr && result.stderr.trim()) {
            output += (output ? '\nError:\n' : '') + result.stderr;
        }

        // Note: Your original compiler did not return 'executionTime'.
        // If it does, you can parse it from the 'result' object here.
        // const executionTime = result.executionTime || 0;

        return {
            output: output.trim() || 'Execution finished with no output.',
            stdout: result.stdout || '',
            stderr: result.stderr || '',
            status: result.status || 'unknown'
            // executionTime: executionTime // Add this back if your service provides it
        };

    } catch (error) {
        console.error("[Custom Compiler] Fetch or JSON Parsing Error:", error);
        // Don't expose internal URLs or stack traces directly to the client
        if (error.message.startsWith('Compiler Service Error:')) {
            throw error; // Re-throw compiler errors
        }
        throw new Error(`Server error communicating with the compilation service.`);
    }
}

module.exports = router;

const studentAuthMiddleware = async (req, res, next) => {
    const authHeader = req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }
    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        // Ensure the token is for a student role if this middleware is specific
        if (decoded.user.role !== 'Student') {
             return res.status(403).json({ message: 'Access denied. Student role required.' });
        }

        // Fetch user data to ensure account is still active/valid
        const { Item } = await docClient.send(new GetCommand({
            TableName: HIRING_TABLE, // Assuming students are in the main user table
            Key: { email: decoded.user.email }
        }));

        if (!Item || Item.isBlocked) {
            return res.status(401).json({ message: 'User not found or account blocked.' });
        }

        // Attach user info (excluding password) to the request object
        req.user = {
            email: Item.email,
            fullName: Item.fullName,
            college: Item.college,
            role: Item.role
            // Add other necessary fields
        };
        next();
    } catch (e) {
        console.error("Auth Middleware Error:", e.message);
        res.status(401).json({ message: 'Token is not valid' });
    }
};


// In your backend.js file, find the io.on('connection', ...) block
// and REPLACE the entire block with this new, updated logic.
// This adds timers, question stats, and better state management.

// =================================================================
// --- REAL-TIME QUIZCOM LOGIC WITH WEBSOCKETS (UPDATED) ---
// =================================================================
const liveQuizData = {}; 

io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);

    // --- QuizCom Logic (no changes) ---
    socket.on('join-room', (liveQuizId) => {
        socket.join(liveQuizId);
        console.log(`Socket ${socket.id} joined room ${liveQuizId}`);
    });
    
    socket.on('student-joined', async ({ liveQuizId, studentDetails }) => {
        try {
            const { Item: liveQuiz } = await docClient.send(new GetCommand({ TableName: "TestifyLiveQuizzes", Key: { liveQuizId } }));
            if (liveQuiz) {
                let updatedParticipants = [...(liveQuiz.participants || [])];
                const existingParticipantIndex = updatedParticipants.findIndex(p => p.email === studentDetails.email);

                if (existingParticipantIndex > -1) {
                    updatedParticipants[existingParticipantIndex].socketId = socket.id;
                } else {
                    const newParticipant = { ...studentDetails, socketId: socket.id, score: 0 };
                    updatedParticipants.push(newParticipant);
                }

                await docClient.send(new UpdateCommand({
                    TableName: "TestifyLiveQuizzes",
                    Key: { liveQuizId },
                    UpdateExpression: "set participants = :p",
                    ExpressionAttributeValues: { ":p": updatedParticipants }
                }));
                io.to(liveQuizId).emit('update-participants', updatedParticipants);
            }
        } catch (error) { console.error("Error on student-joined:", error); }
    });

    socket.on('moderator-next-question', async ({ liveQuizId }) => {
        try {
            if (liveQuizData[liveQuizId] && liveQuizData[liveQuizId].interval) {
                clearInterval(liveQuizData[liveQuizId].interval);
            }

            let { Item: liveQuiz } = await docClient.send(new GetCommand({ TableName: "TestifyLiveQuizzes", Key: { liveQuizId } }));
            if (!liveQuiz) return;
            
            const { Item: originalQuiz } = await docClient.send(new GetCommand({ TableName: "TestifyTests", Key: { testId: liveQuiz.originalQuizId } }));
            if (!originalQuiz) return;

            const nextIndex = liveQuiz.currentQuestionIndex + 1;
            
            if (nextIndex < originalQuiz.questions.length) {
                const question = originalQuiz.questions[nextIndex];
                const questionStartTime = Date.now();
                
                liveQuizData[liveQuizId] = { ...liveQuizData[liveQuizId], questionStartTime };

                await docClient.send(new UpdateCommand({
                    TableName: "TestifyLiveQuizzes",
                    Key: { liveQuizId },
                    UpdateExpression: "set currentQuestionIndex = :idx, #s = :status, answeredBy = :empty",
                    ExpressionAttributeNames: { "#s": "status" },
                    ExpressionAttributeValues: { ":idx": nextIndex, ":status": "active", ":empty": [] }
                }));

                const { correctAnswer, correctAnswers, ...questionForStudent } = question;
                
                io.to(liveQuizId).emit('new-question', {
                    question: questionForStudent,
                    questionIndex: nextIndex,
                    totalQuestions: originalQuiz.questions.length
                });

                io.to(liveQuizId).emit('moderator-new-question', {
                     question: question,
                     questionIndex: nextIndex,
                     totalQuestions: originalQuiz.questions.length
                });

                let timeLeft = question.time || 30;
                liveQuizData[liveQuizId].interval = setInterval(() => {
                    timeLeft--;
                    io.to(liveQuizId).emit('question-timer-update', timeLeft);
                    if (timeLeft <= 0) {
                        clearInterval(liveQuizData[liveQuizId].interval);
                        endQuestionAndShowStats(liveQuizId);
                    }
                }, 1000);

            } else {
                io.to(liveQuizId).emit('quiz-ended', { finalLeaderboard: liveQuiz.participants });
                 await docClient.send(new UpdateCommand({
                    TableName: "TestifyLiveQuizzes", Key: { liveQuizId },
                    UpdateExpression: "set #s = :status",
                    ExpressionAttributeNames: { "#s": "status" },
                    ExpressionAttributeValues: { ":status": "completed" }
                }));
            }
        } catch (error) { console.error("Next Question Error:", error); }
    });
    
    socket.on('student-submit-answer', async ({ liveQuizId, questionIndex, answer }) => {
        try {
            let { Item: liveQuiz } = await docClient.send(new GetCommand({ TableName: "TestifyLiveQuizzes", Key: { liveQuizId } }));
            const { Item: originalQuiz } = await docClient.send(new GetCommand({ TableName: "TestifyTests", Key: { testId: liveQuiz.originalQuizId } }));
            
            const participantIndex = liveQuiz.participants.findIndex(p => p.socketId === socket.id);
            if (participantIndex === -1) return;

            const participantEmail = liveQuiz.participants[participantIndex].email;
            if (liveQuiz.answeredBy && liveQuiz.answeredBy.some(a => a.email === participantEmail)) return;

            const submissionTime = Date.now();
            const question = originalQuiz.questions[questionIndex];
            let isCorrect = false;

            if (question.type === 'single' || question.type === 'blank') {
                isCorrect = String(answer).trim().toLowerCase() === String(question.correctAnswer).trim().toLowerCase();
            } else if (question.type === 'multiple') {
                 const correctSet = new Set(question.correctAnswers.map(String));
                 const answerSet = new Set(answer.map(String));
                 isCorrect = correctSet.size === answerSet.size && [...correctSet].every(val => answerSet.has(val));
            }

            if (isCorrect) {
                const questionStartTime = liveQuizData[liveQuizId]?.questionStartTime || (submissionTime - 1000);
                const timeTaken = (submissionTime - questionStartTime) / 1000;
                const totalTime = question.time || 30;
                
                const basePoints = question.points || 10;
                const timeBonus = Math.max(0, (totalTime - timeTaken) / totalTime);
                const pointsAwarded = basePoints + Math.round(basePoints * timeBonus);

                liveQuiz.participants[participantIndex].score += pointsAwarded;
            }
            
            liveQuiz.answeredBy.push({ email: participantEmail, submissionTime, isCorrect });

            await docClient.send(new UpdateCommand({
                TableName: "TestifyLiveQuizzes", Key: { liveQuizId },
                UpdateExpression: "set participants = :p, answeredBy = :a",
                ExpressionAttributeValues: { ":p": liveQuiz.participants, ":a": liveQuiz.answeredBy }
            }));
            
            io.to(liveQuizId).emit('question-stats-update', { 
                answeredCount: liveQuiz.answeredBy.length, 
                totalCount: liveQuiz.participants.length 
            });

            if(liveQuiz.answeredBy.length === liveQuiz.participants.length) {
                if(liveQuizData[liveQuizId] && liveQuizData[liveQuizId].interval) {
                    clearInterval(liveQuizData[liveQuizId].interval);
                }
                endQuestionAndShowStats(liveQuizId);
            }
            
        } catch(error) { console.error("Submit Answer Error:", error); }
    });

    socket.on('moderator-pause-quiz', ({ liveQuizId }) => io.to(liveQuizId).emit('quiz-paused'));
    socket.on('moderator-resume-quiz', ({ liveQuizId }) => io.to(liveQuizId).emit('quiz-resumed'));
    socket.on('moderator-show-leaderboard', async ({ liveQuizId }) => {
        const { Item: liveQuiz } = await docClient.send(new GetCommand({ TableName: "TestifyLiveQuizzes", Key: { liveQuizId } }));
        if(liveQuiz) io.to(liveQuizId).emit('update-leaderboard', liveQuiz.participants);
    });
     socket.on('moderator-end-quiz', async ({ liveQuizId }) => {
        const { Item: liveQuiz } = await docClient.send(new GetCommand({ TableName: "TestifyLiveQuizzes", Key: { liveQuizId } }));
        if(liveQuiz) {
            io.to(liveQuizId).emit('quiz-ended', { finalLeaderboard: liveQuiz.participants });
             await docClient.send(new UpdateCommand({
                TableName: "TestifyLiveQuizzes", Key: { liveQuizId },
                UpdateExpression: "set #s = :status",
                ExpressionAttributeNames: { "#s": "status" },
                ExpressionAttributeValues: { ":status": "completed" }
            }));
        }
    });

    // =================================================================
    // --- NEW & UPDATED INTERVIEW SOCKET LOGIC ---
    // =================================================================

    /**
     * @event   join-interview-room
     * @desc    User (student or interviewer) joins a room.
     * Fetches and emits the full interview state to the joining user.
     * This handles reloads and reconnects.
     */
    socket.on('join-interview-room', async ({ slotId, role }) => {
        if (!slotId || !role) {
            console.error('[Socket] Invalid join-interview-room event:', { slotId, role });
            return;
        }
        socket.join(slotId);
        console.log(`[Socket] User (Role: ${role}, ID: ${socket.id}) joined interview room: ${slotId}`);

        try {
            // Fetch the current state of the interview slot
            const { Items } = await docClient.send(new QueryCommand({
                TableName: HIRING_INTERVIEWS_TABLE,
                IndexName: "GSI2Index", 
                KeyConditionExpression: "GSI2_PK = :sid",
                ExpressionAttributeValues: { ":sid": slotId }
            }));

            if (!Items || Items.length === 0) {
                console.warn(`[Socket] No slot data found for ${slotId} on join.`);
                return;
            }
            const slotData = Items[0];

            // Emit the persisted state *only* to the user who just joined
            // This is the CRITICAL part for restoring the problem list and code.
            socket.emit('interview-state-restore', {
                chatHistory: slotData.chatHistory || [],
                // This line sends the entire saved array back to the frontend
                assignedProblems: slotData.assignedProblems || [], 
                latestCode: slotData.latestCode || '',
                latestLanguage: slotData.latestLanguage || 'javascript',
                currentProblemId: slotData.currentProblemId || null
            });
            
            // Immediately broadcast the full list to the student only if the role is student,
            // as this is what the student's frontend listener relies on when joining.
            if (role === 'student') {
                 socket.emit('student-receive-problem-list', slotData.assignedProblems || []);
            }


            console.log(`[Socket] Restored state for ${role} in room ${slotId}`);

        } catch (error) {
            console.error(`[Socket] Error fetching slot state for ${slotId} on join:`, error);
        }
        
        // Notify the *other* user that someone joined
        socket.to(slotId).emit('user-joined', { role });
    });
    

    /**
     * @event   send-chat-message
     * @desc    Receives a chat message from a user.
     * Saves it to the DB, then broadcasts it to all.
     */
    socket.on('send-chat-message', async ({ slotId, message }) => {
        if (!slotId || !message) return;
        
        try {
            // Find the slot's real PK/SK to update it
            const { Items } = await docClient.send(new QueryCommand({
                TableName: HIRING_INTERVIEWS_TABLE,
                IndexName: "GSI2Index", 
                KeyConditionExpression: "GSI2_PK = :sid",
                ExpressionAttributeValues: { ":sid": slotId }
            }));
            
            if (!Items || Items.length === 0) return;
            const slotItem = Items[0];

            // Save the message to the DB
            await docClient.send(new UpdateCommand({
                TableName: HIRING_INTERVIEWS_TABLE,
                Key: { PK: slotItem.PK, SK: slotItem.SK },
                UpdateExpression: "SET chatHistory = list_append(if_not_exists(chatHistory, :empty_list), :msg)",
                ExpressionAttributeValues: {
                    ":msg": [message],
                    ":empty_list": []
                }
            }));
            
            // Broadcast the message to everyone *including* the sender
            io.to(slotId).emit('receive-chat-message', message);
            console.log(`[Socket] Chat message saved and broadcasted for ${slotId}`);
            
        } catch (error) {
            console.error(`[Socket] Error saving chat message for ${slotId}:`, error);
        }
    });

    /**
     * @event   interviewer-assign-problem
     * @desc    Interviewer assigns a problem.
     * Saves the updated list of problems to the DB.
     * Broadcasts the *full updated list* to all.
     */
    socket.on('interviewer-assign-problem', async ({ slotId, problem }) => {
        if (!slotId || !problem) {
            console.error('[Socket] Invalid interviewer-assign-problem event:', { slotId, problem });
            return;
        }
        
        try {
            // 1. Query the slot item using GSI2 to get its PK/SK
            const { Items } = await docClient.send(new QueryCommand({
                TableName: HIRING_INTERVIEWS_TABLE,
                IndexName: "GSI2Index", 
                KeyConditionExpression: "GSI2_PK = :sid",
                ExpressionAttributeValues: { ":sid": slotId }
            }));
            
            if (!Items || Items.length === 0) return;
            const slotItem = Items[0];
            
            // Ensure the problem object has a proper ID field for tracking
            const problemId = problem.id || problem.problemId;
            if (!problemId) {
                console.error('[Socket] Problem object missing a unique ID:', problem);
                return;
            }

            // 2. Load and UPDATE the array of problems (Persistence Fix)
            let existingProblems = slotItem.assignedProblems || [];
            
            // Check if this problem is already in the list (e.g., if interviewer re-sends)
            const existingIndex = existingProblems.findIndex(p => (p.id || p.problemId) === problemId);
            
            if (existingIndex === -1) {
                // If it's a new problem, push it to the list
                existingProblems.push(problem);
            } else {
                // If it exists, overwrite it (in case the interviewer modified the problem before re-sending)
                existingProblems[existingIndex] = problem;
            }
            
            // 3. Save the full new list and the current selected problem ID
            await docClient.send(new UpdateCommand({
                TableName: HIRING_INTERVIEWS_TABLE,
                Key: { PK: slotItem.PK, SK: slotItem.SK },
                UpdateExpression: "SET assignedProblems = :list, currentProblemId = :pid",
                ExpressionAttributeValues: {
                    ":list": existingProblems, // Save the entire array (persistence fix)
                    ":pid": problemId          // Set the latest assigned problem as the current one
                }
            }));
            
            // 4. Broadcast the full new list to the room
            io.to(slotId).emit('student-receive-problem-list', existingProblems);
            console.log(`[Socket] Assigned problem ${problemId}. Total stored problems: ${existingProblems.length} in room ${slotId}`);

        } catch (error) {
            console.error(`[Socket] Error assigning problem for ${slotId}:`, error);
        }
    });

    /**
     * @event   student-code-update
     * @desc    Student is typing code.
     * Saves the code and language to the DB.
     * Broadcasts the code to the interviewer.
     */
    socket.on('student-code-update', async ({ slotId, code, language }) => {
        if (!slotId || code === undefined) {
            return;
        }
        
        try {
            const { Items } = await docClient.send(new QueryCommand({
                TableName: HIRING_INTERVIEWS_TABLE,
                IndexName: "GSI2Index", 
                KeyConditionExpression: "GSI2_PK = :sid",
                ExpressionAttributeValues: { ":sid": slotId }
            }));
            
            if (!Items || Items.length === 0) return;
            const slotItem = Items[0];
            
            // Save latest code and language to DB
            await docClient.send(new UpdateCommand({
                TableName: HIRING_INTERVIEWS_TABLE,
                Key: { PK: slotItem.PK, SK: slotItem.SK },
                UpdateExpression: "SET latestCode = :code, latestLanguage = :lang",
                ExpressionAttributeValues: {
                    ":code": code,
                    ":lang": language
                }
            }));
            
            // Send to interviewer
            socket.to(slotId).emit('interviewer-receive-code', { code, language });

        } catch (error) {
            // Don't log this one, it's too noisy
            // console.error(`[Socket] Error saving code update for ${slotId}:`, error);
        }
    });

    /**
     * @event   student-code-output
     * @desc    Student ran or submitted code.
     * Relays the output to the interviewer.
     */
    socket.on('student-code-output', ({ slotId, outputs, isSubmit }) => {
        if (!slotId || !outputs) return;
        // Just relay to the interviewer
        socket.to(slotId).emit('student-code-output', { outputs, isSubmit });
    });


    // --- Other Socket Events (WebRTC, Violations) ---
    socket.on('student-ready', ({ slotId }) => {
        console.log(`[Socket] Student is ready in room: ${slotId}`);
        socket.to(slotId).emit('student-ready');
    });

    socket.on('interviewer-start-interview', ({ slotId }) => {
        console.log(`[Socket] Interviewer started interview for room: ${slotId}`);
        socket.to(slotId).emit('interview-started');
    });

    socket.on('webrtc-offer', (data) => {
        socket.to(data.slotId).emit('webrtc-offer', data.offer);
    });

    socket.on('webrtc-answer', (data) => {
        socket.to(data.slotId).emit('webrtc-answer', data.answer);
    });

    socket.on('webrtc-ice-candidate', (data) => {
        socket.to(data.slotId).emit('webrtc-ice-candidate', data.candidate);
    });

    socket.on('interviewer-end-interview', ({ slotId }) => {
        console.log(`[Socket] Interviewer ended interview for room: ${slotId}`);;
        socket.to(slotId).emit('interview-end'); // Tell student it's over
    });

    socket.on('student-violation-count', (data) => {
        // FIX: The slotId was not defined. It needs to be destructured from the 'data' object.
        const { slotId, count } = data;
        if (!slotId) {
            console.error("[Socket] Received 'student-violation-count' without a slotId.");
            return;
        }
        // Use data.slotId (or the destructured slotId) here instead of the undefined 'slotId'
        socket.to(slotId).emit('student-violation-count', { count: count });
    });
    
    socket.on('disconnect', () => console.log('User disconnected:', socket.id));

    socket.on('moderator-join', () => {
    console.log(`[PROCTORING] Moderator ${socket.id} joined the dashboard.`);
    socket.join(MODERATOR_ROOM_ID);
});

// [REPLACE your entire io.on('connection', ...) block with this one]

// This object will track which students are in which test


    socket.on('moderator-join-test', (data) => {
        const { testId } = data;
        if (!testId) return;

        console.log(`[PROCTORING] Moderator ${socket.id} joined dashboard for test ${testId}.`);
        socket.join(testId); // Join the room for this testId

        // Send the moderator all students who are *already* in the session
        const existingStudents = liveTestSessions[testId] || [];
        socket.emit('existing-students', existingStudents);
    });

    socket.on('student-join', (data) => {
        const { testId, candidateDetails, channelARN } = data; // Student now sends their channelARN
        if (!testId || !candidateDetails || !channelARN) {
             console.error("[PROCTORING] Invalid student-join event:", data);
             return;
        }

        const studentInfo = {
            socketId: socket.id,
            testId: testId,
            channelARN: channelARN, // Store the ARN
            candidateDetails: candidateDetails
        };

        console.log(`[PROCTORING] Student ${candidateDetails.fullName} (${socket.id}) joined test ${testId}.`);

        socket.data.studentInfo = studentInfo; 

        // Join the room for this specific test
        socket.join(testId);

        // Add student to our live session tracker
        if (!liveTestSessions[testId]) {
            liveTestSessions[testId] = [];
        }
        liveTestSessions[testId].push(studentInfo);

        // Tell all moderators *in this test's room* a new student is here
        socket.to(testId).emit('new-student-joined', studentInfo);
    });

    socket.on('proctoring-alert', (data) => {
        if (!data.alert || !socket.data.studentInfo) return;

        const testId = socket.data.studentInfo.testId;
        if (!testId) return;

        console.log(`[PROCTORING] Alert from student ${socket.id} in test ${testId}: ${data.alert}`);

        // Send this to all moderators *in this test's room*
        socket.to(testId).emit('proctoring-alert', {
            alert: data.alert,
            studentSocketId: socket.id,
            studentInfo: socket.data.studentInfo
        });
    });

    // Handle 1-to-1 chat
    socket.on('proctoring-chat', (data) => {
        const { targetSocketId, message, isFromModerator } = data;
        if (!targetSocketId || !message) return;

        let senderName;
        let eventName;

        if (isFromModerator) {
            // Message from moderator to student
            senderName = "Moderator";
            eventName = 'proctoring-chat'; // Student listens for this
            console.log(`[CHAT] Moderator ${socket.id} to Student ${targetSocketId}: ${message}`);
        } else {
            // Message from student to moderators
            senderName = socket.data.studentInfo?.candidateDetails?.fullName || "Student";
            eventName = 'proctoring-chat'; // Moderator also listens for this
            console.log(`[CHAT] Student ${socket.id} to Moderator ${targetSocketId}: ${message}`);
        }

        // Emit to the specific target socket (student or moderator)
        socket.to(targetSocketId).emit(eventName, {
            message: message,
            senderName: senderName,
            studentSocketId: isFromModerator ? targetSocketId : socket.id // Always include student ID
        });
    });

    // Handle suspend command
    socket.on('proctoring-command', (data) => {
        const { targetSocketId, command } = data;
        if (!targetSocketId || !command) return;

        console.log(`[PROCTORING] Relaying command '${command}' from ${socket.id} to ${targetSocketId}`);

        socket.to(targetSocketId).emit('proctoring-command', {
            command: command
        });
    });

    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
        if (socket.data.studentInfo) {
            const { testId, socketId } = socket.data.studentInfo;
            console.log(`[PROCTORING] Student ${socket.data.studentInfo.candidateDetails.fullName} disconnected from test ${testId}.`);

            // Remove student from our session tracker
            if (liveTestSessions[testId]) {
                liveTestSessions[testId] = liveTestSessions[testId].filter(student => student.socketId !== socketId);
            }

            // Tell all moderators *in this test's room* this student left
            socket.to(testId).emit('student-left', {
                studentSocketId: socket.id,
                studentInfo: socket.data.studentInfo
            });
        }
    });
});



async function endQuestionAndShowStats(liveQuizId) {
    try {
        const { Item: liveQuiz } = await docClient.send(new GetCommand({ TableName: "TestifyLiveQuizzes", Key: { liveQuizId } }));
        if (liveQuiz) {
            let fastestCorrect = null;
            const correctAnswers = (liveQuiz.answeredBy || []).filter(a => a.isCorrect);
            if(correctAnswers.length > 0) {
                correctAnswers.sort((a,b) => a.submissionTime - b.submissionTime);
                const fastestEmail = correctAnswers[0].email;
                const fastestParticipant = liveQuiz.participants.find(p => p.email === fastestEmail);
                if (fastestParticipant) {
                    const timeTaken = (correctAnswers[0].submissionTime - (liveQuizData[liveQuizId]?.questionStartTime || 0)) / 1000;
                    fastestCorrect = {
                        fullName: fastestParticipant.fullName,
                        time: timeTaken.toFixed(2)
                    };
                }
            }
            
            io.to(liveQuizId).emit('question-ended', { 
                questionLeaderboard: liveQuiz.participants,
                fastestCorrectAnswer: fastestCorrect
            });
        }
    } catch(error) {
        console.error("End of Question Error:", error);
    }
}
// =================================================================
// --- NEW: INTERVIEWER PORTAL ENDPOINTS ---
// =================================================================

/**
 * @route   GET /api/interviewer/my-schedule
 * @desc    Get the assigned interview schedule for the logged-in interviewer
 * @access  Private (Interviewer)
 */
app.get('/api/interviewer/my-schedule', interviewerAuth, async (req, res) => {
    const interviewerEmail = req.user.email;
    console.log(`[GET /api/interviewer/my-schedule] Fetching schedule for ${interviewerEmail}`);

    try {
        // We assume a GSI named 'InterviewerEmailIndex' on the HIRING_INTERVIEWS_TABLE
        // GSI1PK: interviewerEmail
        // GSI1SK: startTime
        const { Items } = await docClient.send(new QueryCommand({
            TableName: HIRING_INTERVIEWS_TABLE,
            IndexName: "InterviewerEmailIndex",
            KeyConditionExpression: "GSI1_PK = :email", // Corrected to use GSI1_PK
            // We also filter to only get "SLOT" items, not "EVENT" or "EVAL" items
            FilterExpression: "begins_with(SK, :slot_prefix)",
            ExpressionAttributeValues: {
                ":email": interviewerEmail,
                ":slot_prefix": "SLOT#"
            }
        }));

        if (!Items || Items.length === 0) {
            console.log(`[GET /api/interviewer/my-schedule] No slots found for ${interviewerEmail}`);
            return res.json([]);
        }

        console.log(`[GET /api/interviewer/my-schedule] Found ${Items.length} slots. Processing...`);

        const now = new Date();
        
        const schedule = Items.map(item => {
            let status = 'Upcoming';
            const startTime = new Date(item.startTime);
            const endTime = new Date(item.endTime);

            // Determine status
            if (item.interviewStatus === 'COMPLETED') {
                status = 'Completed';
            } else if (now >= startTime && now < endTime) {
                status = 'Active';
            } else if (now > endTime) {
                // If the time is past but status isn't "COMPLETED", mark as "Pending Evaluation" or "Expired"
                status = 'Pending Evaluation'; 
            }

            return {
                slotId: item.slotId, // This is the simple UUID for the slot
                candidateName: item.candidateName,
                candidateEmail: item.candidateEmail,
                startTime: item.startTime,
                status: status
            };
        });

        // The query should already sort by startTime (as it's the GSI SK),
        // but we sort again just in case.
        schedule.sort((a, b) => new Date(a.startTime) - new Date(b.startTime));

        res.json(schedule);

    } catch (error) {
        console.error(`[GET /api/interviewer/my-schedule] Error fetching schedule for ${interviewerEmail}:`, error);
        if (error.name === "ValidationException" && error.message.includes("index")) {
             console.error("[FATAL] Missing 'InterviewerEmailIndex' GSI on 'HiringInterviews' table.");
             return res.status(500).json({ message: "Server configuration error: Database index missing." });
        }
        res.status(500).json({ message: 'Server error fetching schedule.' });
    }
});


// --- AWS DYNAMODB CLIENT SETUP ---
const client = new DynamoDBClient({
    region: 'ap-south-1',
    credentials: {
        accessKeyId: 'AKIAT4YSUMZD755UHGW7',
        secretAccessKey: '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'
    }
});
const docClient = DynamoDBDocumentClient.from(client);

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
app.get('/Beta-Version', (req, res) => res.sendFile(path.join(__dirname, 'public', 'mock.html')));
app.get('/HireWithUs', (req, res) => res.sendFile(path.join(__dirname, 'public', 'HireWithUs.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));




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
app.get('/student/quiz-join', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student', 'quiz-join.html')));



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

//hiring interviewer portal routes
app.get('/interviewer/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'interviewer', 'dashboard.html')));
app.get('/interviewer/interview-page', (req, res) => res.sendFile(path.join(__dirname, 'public', 'interviewer', 'interview-page.html')));
app.get('/interviewer/my-schedule', (req, res) => res.sendFile(path.join(__dirname, 'public', 'interviewer', 'my-schedule.html')));

//hiring candidate portal routes
app.get('/candidate/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'candidate', 'dashboard.html')));
app.get('/candidate/interview-page', (req, res) => res.sendFile(path.join(__dirname, 'public', 'candidate', 'interview-page.html')));
app.get('/candidate/join-interview', (req, res) => res.sendFile(path.join(__dirname, 'public', 'candidate', 'join-interview.html')));

// jobportal routes
// Job Portal Routes
app.get('/jobportal/job-application', (req, res) => 
    res.sendFile(path.join(__dirname, 'public', 'jobportal', 'job-application.html'))
);

app.get('/jobportal/student-edit-application', (req, res) => 
    res.sendFile(path.join(__dirname, 'public', 'jobportal', 'student-edit-application.html'))
);

app.get('/jobportal/student-interview-room', (req, res) => 
    res.sendFile(path.join(__dirname, 'public', 'jobportal', 'student-interview-room.html'))
);

app.get('/jobportal/student-job-board', (req, res) => 
    res.sendFile(path.join(__dirname, 'public', 'jobportal', 'student-job-board.html'))
);

app.get('/jobportal/student-login', (req, res) => 
    res.sendFile(path.join(__dirname, 'public', 'jobportal', 'student-login.html'))
);

app.get('/jobportal/student-my-applications', (req, res) => 
    res.sendFile(path.join(__dirname, 'public', 'jobportal', 'student-my-applications.html'))
);

app.get('/jobportal/student-my-tests', (req, res) => 
    res.sendFile(path.join(__dirname, 'public', 'jobportal', 'student-my-tests.html'))
);

app.get('/jobportal/student-register', (req, res) => 
    res.sendFile(path.join(__dirname, 'public', 'jobportal', 'student-regsiter.html'))
);

// hiring moderator portal routes

app.get('/hiring/assign-coding-test', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-assign-coding-test.html')));
app.get('/hiring/assign-test', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-assign-test.html')));
app.get('/hiring/coding-test-results', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-coding-test-results.html')));
app.get('/hiring/create-coding-test', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-create-coding-test.html')));
app.get('/hiring/create-job', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-create-job.html')));
app.get('/hiring/create-problem', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-create-problem.html')));
app.get('/hiring/create-test', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-create-test.html')));
app.get('/hiring/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-dashboard.html')));
app.get('/hiring/interview-reports', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-interview-reports.html')));
app.get('/hiring/jobs', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-jobs.html')));
app.get('/hiring/manage-colleges', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-manage-colleges.html')));
app.get('/hiring/manage-interviewers', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-manage-interviewers.html')));
app.get('/hiring/manage-tests', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-manage-tests.html')));
app.get('/hiring/moderator-login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-moderator-login.html')));
app.get('/hiring/report-details', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-report-details.html')));
app.get('/hiring/schedule-interview', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-schedule-interview.html')));
app.get('/hiring/test-history', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-test-history.html')));
app.get('/hiring/test-reports', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-test-reports.html')));
app.get('/hiring/view-applicants', (req, res) => res.sendFile(path.join(__dirname, 'public', 'hiring', 'hiring-view-applicants.html')));




app.use(express.static('public'));
app.use('/moderator', express.static(path.join(__dirname, 'public/moderator')));


// =================================================================
// --- PERMANENT FIX FOR SERVING ZOOM SDK LOCALLY ---
// This line serves the files from the package you installed with NPM.
// It correctly points to the '@zoom/meetingsdk' directory.
// =================================================================


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
const authMiddleware = async (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user;

        // For internal users, verify they exist and are not blocked.
        // For external hiring candidates (isExternal: true), this check is skipped.
        if (!req.user.isExternal) {
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
        }

        next(); // Allows the request to proceed for all valid tokens.
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

const quizModeratorAuth = (req, res, next) => {
    if (req.user.role !== 'QuizCom Moderator') {
        return res.status(403).json({ message: 'Access denied. QuizCom Moderator role required.' });
    }
    next();
};
//=================================================================
//--- OTP IMPLEMENTATION ---
//=================================================================
//In-memory store for OTPs. In a real application, use a database with TTL.
const otpStore = {};

// UPDATED ENDPOINT: Send OTP to user's email, no more new tabs.
app.post('/api/send-otp', async (req, res) => {
    // The mobile number is collected on the frontend but not used for OTP.
    // We only need the email for this new flow.
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ message: 'Email is required.' });
    }

    try {
        // Check if user already exists
        const existingUser = await docClient.send(new GetCommand({ TableName: "TestifyUsers", Key: { email: email.toLowerCase() } }));
        if (existingUser.Item) {
            return res.status(400).json({ message: 'An account with this email already exists.' });
        }

        // Generate a 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        // Set OTP to expire in 5 minutes
        const expirationTime = Date.now() + 5 * 60 * 1000;

        // Store the OTP and its expiration time
        otpStore[email.toLowerCase()] = { otp, expirationTime };
        console.log(`Generated OTP for ${email}: ${otp}`); // For debugging

        // Email content
        const mailOptions = {
            to: email,
            subject: 'Your TESTIFY Verification Code',
            html: `
                <div style="font-family: Arial, sans-serif; text-align: center; color: #333; padding: 20px;">
                    <img src="[https://res.cloudinary.com/dpz44zf0z/image/upload/v1756037774/Gemini_Generated_Image_eu0ib0eu0ib0eu0i_z0amjh.png](https://res.cloudinary.com/dpz44zf0z/image/upload/v1756037774/Gemini_Generated_Image_eu0ib0eu0ib0eu0i_z0amjh.png)" alt="Testify Logo" style="height: 50px; margin-bottom: 20px;">
                    <h2>Verify Your Account</h2>
                    <p>Here is your One-Time Password (OTP) to complete your account creation.</p>
                    <p style="font-size: 28px; font-weight: bold; letter-spacing: 4px; color: #4F46E5; background-color: #f0f0f0; padding: 15px; border-radius: 8px; display: inline-block;">
                        ${otp}
                    </p>
                    <p style="margin-top: 20px;">This OTP is valid for 5 minutes. Please do not share it with anyone.</p>
                </div>
            `
        };

        // Send the email (using the existing SES function in your code)
        await sendEmailWithSES(mailOptions);

        res.status(200).json({ message: 'OTP sent successfully. Please check your email.' });

    } catch (error) {
        console.error("Send OTP Error:", error);
        res.status(500).json({ message: 'Server error sending OTP. Please try again.' });
    }
});

// const otpStore = {};

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
//         const expirationTime = Date.now() + 5 * 60 * 1000; // 5 minutes
//         const verificationToken = uuidv4();

//         otpStore[email.toLowerCase()] = { otp, expirationTime, verificationToken };
//         console.log(`Generated OTP for ${email}: ${otp}`);

//         // Construct the verification link that will be opened in a new tab
//         const verificationLink = `/verify-otp.html?token=${verificationToken}`;

//         // Send the link back to the frontend instead of sending an email
//         res.status(200).json({ 
//             message: 'Verification token generated.',
//             verificationLink: verificationLink 
//         });

//     } catch (error) {
//         console.error("Send OTP Error:", error);
//         res.status(500).json({ message: 'Server error generating verification code. Please try again.' });
//     }
// });

// // Endpoint to get OTP using the secure token from the verification page
// app.post('/api/get-otp-by-token', (req, res) => {
//     const { token } = req.body;
//     if (!token) {
//         return res.status(400).json({ message: 'Verification token is missing.' });
//     }

//     const email = Object.keys(otpStore).find(key => otpStore[key].verificationToken === token);

//     if (!email) {
//         return res.status(404).json({ message: 'This verification link is invalid or has already been used.' });
//     }

//     const otpData = otpStore[email];

//     if (Date.now() > otpData.expirationTime) {
//         delete otpStore[email];
//         return res.status(400).json({ message: 'This verification link has expired.' });
//     }
    
//     res.json({ otp: otpData.otp });
    
//     // Invalidate the token after use
//     delete otpStore[email];
// });


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
    from: '"TESTIFY" <support@testify-lac.com>',
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
                                Houston, TX, USA | <a href="mailto:support@testify-lac.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
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



       await sendEmailWithSES(mailOptions);
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
    // Now also expecting 'otp' from the form
    const { otp, fullName, email, mobile, college, department, year, rollNumber, password } = req.body;

    if (!otp) {
        return res.status(400).json({ message: 'Verification code is required.' });
    }

    // --- OTP Verification Logic ---
    const emailLower = email.toLowerCase();
    const storedOtpData = otpStore[emailLower];

    if (!storedOtpData) {
        return res.status(400).json({ message: 'Invalid or expired verification code. Please request a new one.' });
    }
    if (storedOtpData.otp !== otp) {
        return res.status(400).json({ message: 'The verification code is incorrect.' });
    }
    if (Date.now() > storedOtpData.expirationTime) {
        delete otpStore[emailLower]; // Clean up expired OTP
        return res.status(400).json({ message: 'Verification code has expired. Please request a new one.' });
    }
    // --- End of OTP Verification ---

    // Validate that all other required fields are present
    if (!fullName || !email || !mobile || !college || !department || !year || !rollNumber || !password) {
        return res.status(400).json({ message: 'Please fill all fields.' });
    }

    try {
        // Check if a user with the same email already exists (double-check)
        const existingUser = await docClient.send(new GetCommand({
            TableName: "TestifyUsers",
            Key: { email: emailLower }
        }));
        if (existingUser.Item) {
            delete otpStore[emailLower]; // Clean up OTP
            return res.status(400).json({ message: 'User with this email already exists.' });
        }

        // OTP is valid, so we can delete it now
        delete otpStore[emailLower];

        // Hash the password for security
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create the new user object
        const newUser = {
            email: emailLower,
            fullName,
            mobile,
            college,
            year,
            department,
            rollNumber,
            password: hashedPassword,
            role: "Student",
            isBlocked: false
        };

        // Save the new user to the database
        await docClient.send(new PutCommand({ TableName: "TestifyUsers", Item: newUser }));

        res.status(201).json({ message: 'Account created successfully! Redirecting to login...' });

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
        from: '"TESTIFY" <support@testify-lac.com>',
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
                                Houston, TX, USA | <a href="mailto:support@testify-lac.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
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

           await sendEmailWithSES(mailOptions);
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
        // --- FIX APPLIED HERE ---
        // We now filter the scan to only include items that are tests.
        // Meetings have an "isMeeting" attribute, so we select items where that attribute does not exist.
        const { Items: tests } = await docClient.send(new ScanCommand({ 
            TableName: "TestifyTests",
            FilterExpression: "attribute_not_exists(isMeeting)"
        }));

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
        from: '"TESTIFY" <support@testify-lac.com>',
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
                                Houston, TX, USA | <a href="mailto:support@testify-lac.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
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


           await sendEmailWithSES(mailOptions);
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
    from: '"TESTIFY" <support@testify-lac.com>',
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
                                Houston, TX, USA | <a href="mailto:support@testify-lac.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
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

               await sendEmailWithSES(mailOptions);
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
        // Logic to handle the static test case from the request body
        if (testId === 'cognizant-cloud-fundamentals-static' && testData) {
            test = testData;
        } else {
            // Logic for dynamic tests from the database
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
            violationReason: violationReason || null,
            // FIX: Save the static test data with the result if it exists
            staticTestData: testData || null 
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
    from: '"TESTIFY" <support@testify-lac.com>',
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
                                Houston, TX, USA | <a href="mailto:support@testify-lac.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
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


           await sendEmailWithSES(mailOptions);
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

    // Basic validation
    if (!language || code === undefined || code === null) { // Allow empty code, but not missing
        return res.status(400).json({
            message: 'Language and code are required.'
        });
    }

    try {
        // Use the new helper function
        const result = await compileWithCustomCompiler(language, code, input);
        // Send back the structured result
        res.json({
            output: result.output, // Combined stdout/stderr for basic display
            stdout: result.stdout,
            stderr: result.stderr,
            status: result.status // Include the status from the compiler API
        });
    } catch (error) {
        console.error("[/api/compile] Error:", error);
        // Send a generic server error and the error message from the helper
        res.status(500).json({
            message: 'Server error during compilation.',
            // Send the specific error message from the helper for debugging on client-side if needed
            output: error.message
        });
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
    from: '"TESTIFY" <support@testify-lac.com>',
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
                                Houston, TX, USA | <a href="mailto:support@testify-lac.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
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



       await sendEmailWithSES(mailOptions);
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
        from: '"TESTIFY" <support@testify-lac.com>',
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
                                Houston, TX, USA | <a href="mailto:support@testify-lac.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
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
               await sendEmailWithSES(mailOptions);
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
                    from: '"TESTIFY" <support@testify-lac.com>',
                    to: studentEmails.join(','),
                    subject: `New Coding Contest Assigned: ${title}`,
                    html: `<p>Hello,</p><p>A new coding contest, "<b>${title}</b>", has been assigned to you. Please log in to your TESTIFY dashboard to participate.</p><p>Best regards,<br/>The TESTIFY Team</p>`
                };
               await sendEmailWithSES(mailOptions);
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
                from: '"TESTIFY" <support@testify-lac.com>',
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
                                Houston, TX, USA | <a href="mailto:support@testify-lac.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
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
           await sendEmailWithSES(mailOptions);
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
    // FIX: Added 'applicationDeadline' to be read from the request body
    const { title, location, department, description, applicationDeadline } = req.body;
    if (!title || !location || !department || !description || !applicationDeadline) {
        // FIX: Added deadline to validation check
        return res.status(400).json({ message: 'All job fields, including deadline, are required.' });
    }
    const jobId = `job_${uuidv4()}`;
    const newJob = {
        jobId,
        title,
        location,
        department,
        description,
        applicationDeadline, // FIX: Added deadline to the new job object
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
            TableName: APPLICATIONS_TABLE_NAME, // <--- UPDATED TABLE
            FilterExpression: "jobId = :jid",
            ExpressionAttributeValues: { ":jid": jobId }
        }));

        if (Items) {
            Items.sort((a, b) => new Date(b.appliedAt) - new Date(a.appliedAt));
        }
        
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
/**
 * @route   POST /api/careers/apply/:jobId
 * @desc    Public: Submit a detailed job application with file uploads
 * @access  Public
 */
app.post('/api/careers/apply/:jobId',
    upload.any(), // Use upload.any() to accept all files with dynamic names
    async (req, res) => {
        const { jobId } = req.params;
        const {
            firstName, lastName, email, phone,
            address, city, country,
            education, experiences,
            linkedinUrl, githubUrl, portfolioUrl,
            coverLetter, govtIdType
        } = req.body;

        if (!firstName || !lastName || !email || !phone || !address || !city || !country) {
            return res.status(400).json({ message: 'Personal details, including address, city, and country, are required.' });
        }

        try {
            const { Item: job } = await docClient.send(new GetCommand({ 
                TableName: CORRECT_JOBS_TABLE_NAME, 
                Key: { jobId: jobId }
            }));

            if (!job) {
                return res.status(404).json({ message: 'Job opening not found.' });
            }

            // Check for duplicate applications
            const { Items: existingApps } = await docClient.send(new ScanCommand({
                TableName: APPLICATIONS_TABLE_NAME, // <--- UPDATED TABLE
                FilterExpression: "jobId = :jid AND (email = :email OR phone = :phone)",
                ExpressionAttributeValues: {
                    ":jid": jobId,
                    ":email": email,
                    ":phone": phone
                },
                Limit: 1
            }));

            if (existingApps && existingApps.length > 0) {
                return res.status(400).json({ message: 'You have already applied for this job with this email or phone number.' });
            }

            // Process file uploads
            const files = req.files;
            let passportPhotoUrl, resumeUrl, govtIdUrl;
            const educationCertificates = {};
            const experienceCertificates = {};

            if (files) {
                for (const file of files) {
                    const result = await uploadToS3(file); // Assumes uploadToS3 helper
                    if (file.fieldname === 'passportPhoto') passportPhotoUrl = result.secure_url;
                    else if (file.fieldname === 'resume') resumeUrl = result.secure_url;
                    else if (file.fieldname === 'govtId') govtIdUrl = result.secure_url;
                    else if (file.fieldname.startsWith('education_certificate_')) educationCertificates[file.fieldname.split('_')[2]] = result.secure_url;
                    else if (file.fieldname.startsWith('experience_certificate_')) experienceCertificates[file.fieldname.split('_')[2]] = result.secure_url;
                }
            }

            if (!passportPhotoUrl || !resumeUrl) {
                return res.status(400).json({ message: 'Passport photo and resume are mandatory.' });
            }

            const educationData = JSON.parse(education || '[]').map((edu, index) => ({
                ...edu,
                certificateUrl: educationCertificates[index] || null
            }));

            const experienceData = JSON.parse(experiences || '[]').map((exp, index) => ({
                ...exp,
                certificateUrl: experienceCertificates[index] || null
            }));
            
            const addressData = { street: address, city: city, country: country };
            const applicationId = `app_${uuidv4()}`;

            const newApplication = {
                applicationId, jobId, jobTitle: job.title,
                firstName, lastName, email, phone,
                address: addressData,
                coverLetter: coverLetter || null,
                passportPhotoUrl, resumeUrl,
                govtId: { type: govtIdType, url: govtIdUrl || null },
                education: educationData,
                experiences: experienceData,
                links: { linkedin: linkedinUrl, github: githubUrl, portfolio: portfolioUrl },
                status: 'Received',
                appliedAt: new Date().toISOString()
            };

            // Save to the "TestifyApplications" table
            await docClient.send(new PutCommand({ TableName: APPLICATIONS_TABLE_NAME, Item: newApplication })); // <--- UPDATED TABLE

            // Send confirmation email (simplified for brevity)
            try {
                const mailOptions = {
                    to: email,
                    subject: `Application Received - ${job.title}`,
                    html: `<!DOCTYPE html>
                        <html lang="en">
                        <head>
                            <meta charset="UTF-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            <title>Application Received</title>
                            <style>
                                @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap');
                                body {
                                    font-family: 'Poppins', Arial, sans-serif;
                                    margin: 0;
                                    padding: 0;
                                    background-color: #f8fafc;
                                    color: #334155;
                                }
                                .container {
                                    width: 90%;
                                    max-width: 600px;
                                    margin: 20px auto;
                                    background-color: #ffffff;
                                    border: 1px solid #e2e8f0;
                                    border-radius: 12px;
                                    overflow: hidden;
                                    box-shadow: 0 4px 12px rgba(0,0,0,0.05);
                                }
                                .header {
                                    padding: 24px;
                                    text-align: center;
                                    border-bottom: 1px solid #e2e8f0;
                                }
                                .header img {
                                    height: 40px;
                                    width: auto;
                                }
                                .content {
                                    padding: 32px;
                                    line-height: 1.6;
                                }
                                .content h1 {
                                    font-size: 22px;
                                    font-weight: 700;
                                    color: #1e293b;
                                    margin-top: 0;
                                    margin-bottom: 16px;
                                }
                                .content p {
                                    font-size: 16px;
                                    margin-bottom: 16px;
                                }
                                .content strong {
                                    color: #1e293b;
                                }
                                .info-box {
                                    background-color: #f8fafc;
                                    border: 1px solid #e2e8f0;
                                    border-radius: 8px;
                                    padding: 20px;
                                    margin: 24px 0;
                                }
                                .info-box p {
                                    margin: 0;
                                    font-size: 15px;
                                }
                                .button-container {
                                    text-align: center;
                                    margin-top: 24px;
                                }
                                .button {
                                    display: inline-block;
                                    background-color: #4f46e5;
                                    color: #ffffff;
                                    text-decoration: none;
                                    padding: 12px 24px;
                                    border-radius: 8px;
                                    font-weight: 500;
                                    font-size: 16px;
                                }
                                .footer {
                                    background-color: #f8fafc;
                                    border-top: 1px solid #e2e8f0;
                                    padding: 24px 32px;
                                    text-align: center;
                                    font-size: 13px;
                                    color: #64748b;
                                }
                            </style>
                        </head>
                        <body>
                            <div class="container">
                                <div class="header">
                                    <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1760704788/XETA_SOLUTIONS_bt6bgn.jpg" alt="Xeta Solutions Logo">
                                </div>
                                <div class="content">
                                    <h1>Thank You For Applying!</h1>
                                    <p>Hello <strong>${firstName}</strong>,</p>
                                    <p>We have successfully received your application for the position of <strong>${job.title}</strong> at <strong>Xeta Solutions</strong>.</p>
                                    
                                    <div class="info-box">
                                        <p>Your Application ID is: <strong>${applicationId}</strong></p>
                                    </div>
                                    
                                    <p>Our hiring team will review your application and will be in touch if your qualifications match our needs. You can check the status of all your applications at any time by visiting the "My Applications" page.</p>
                                    
                                    <div class="button-container">
                                        <a href="https:/testify-lac.com/my-applications" class="button">Check Application Status</a>
                                    </div>
                                    
                                    <p style="margin-top: 24px; margin-bottom: 0;">Best regards,<br>Talent Acquisition Team<br><strong>Xeta Solutions</strong></p>
                                </div>
                                <div class="footer">
                                    &copy; ${new Date().getFullYear()} Xeta Solutions. All rights reserved.
                                </div>
                            </div>
                        </body>
                        </html>`
                };
                await sendEmailWithSES(mailOptions);
            } catch (emailError) {
                console.error(`Failed to send confirmation email to ${email}:`, emailError);
            }

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
app.get('/api/student/applications', studentAuthMiddleware, async (req, res) => {
    // Assuming the authMiddleware populates req.user.email for the logged-in student
    const studentEmail = req.user.email;
    if (!studentEmail) {
        console.error("[MY_APPS_ERROR] studentAuthMiddleware did not populate req.user correctly.");
        return res.status(401).json({ message: 'Authentication required.' });
    }

    console.log(`[MY_APPS_START] Fetching applications for student ${studentEmail}`);

    try {
        // *** FIX APPLIED HERE: Changed IndexName ***
        // Verify this index exists on your HiringApplications table with 'email' as the partition key.
        const correctIndexName = "email-jobId-index"; // <-- CONFIRM THIS NAME IN AWS
        console.log(`[MY_APPS_QUERY] Querying ${HIRING_APPLICATIONS_TABLE} using index: ${correctIndexName} for email: ${studentEmail}`);

        const queryParams = {
            TableName: HIRING_APPLICATIONS_TABLE,
            IndexName: correctIndexName, // Use the corrected index name
            KeyConditionExpression: "email = :emailVal", // Query only by the partition key (email) of the GSI
            ExpressionAttributeValues: { ":emailVal": studentEmail }
        };
        console.log("[MY_APPS_QUERY] Query Params:", queryParams);

        const { Items } = await docClient.send(new QueryCommand(queryParams));

        if (!Items || Items.length === 0) {
            console.log(`[MY_APPS_INFO] No applications found for student ${studentEmail}`);
            return res.json([]); // Return empty array if no applications found
        }
        console.log(`[MY_APPS_INFO] Found ${Items.length} application(s) for student ${studentEmail}. Fetching job details...`);

        // --- Fetch Job Details for Deadlines (BatchGet for efficiency) ---
        const jobIds = [...new Set(Items.map(app => app.jobId))];
        let jobDeadlineMap = new Map();

        if (jobIds.length > 0) {
            const jobKeys = jobIds.map(id => ({ jobId: id })); // Assuming 'jobId' is the PK for HIRING_JOBS_TABLE
            console.log(`[MY_APPS_BATCH_GET] Fetching details for ${jobKeys.length} unique jobs from ${HIRING_JOBS_TABLE}`);

            const batchGetParams = {
                RequestItems: {
                    [HIRING_JOBS_TABLE]: { // Use the correct table name constant
                        Keys: jobKeys,
                        ProjectionExpression: "jobId, applicationDeadline, title" // Fetch title as well
                    }
                }
            };
            console.log("[MY_APPS_BATCH_GET] BatchGet Params:", JSON.stringify(batchGetParams, null, 2));

            const { Responses } = await docClient.send(new BatchGetCommand(batchGetParams));
            const jobs = Responses && Responses[HIRING_JOBS_TABLE] ? Responses[HIRING_JOBS_TABLE] : [];
            jobs.forEach(j => {
                if (j && j.jobId) {
                    // Store both deadline and title
                    jobDeadlineMap.set(j.jobId, { deadline: j.applicationDeadline, title: j.title });
                } else {
                     console.warn(`[MY_APPS_WARN] Missing details for jobId: ${j?.jobId}`);
                }
            });
             console.log(`[MY_APPS_BATCH_GET] Successfully fetched details for ${jobs.length} jobs.`);
        } else {
             console.log(`[MY_APPS_INFO] No job IDs found in applications, skipping BatchGet.`);
        }


        // Enrich application data with the deadline and title from the map
        const enrichedApplications = Items.map(app => {
            const jobInfo = jobDeadlineMap.get(app.jobId);
            return {
                ...app,
                jobTitle: jobInfo?.title || 'Job Title Unavailable', // Add title
                jobDeadline: jobInfo?.deadline || null // Add deadline
            };
        });

        enrichedApplications.sort((a, b) => new Date(b.appliedAt) - new Date(a.appliedAt));

        console.log(`[MY_APPS_SUCCESS] Returning ${enrichedApplications.length} enriched application(s) for student ${studentEmail}`);
        res.json(enrichedApplications);

    } catch (error) {
        console.error(`[MY_APPS_FATAL_ERROR] Failed fetching applications for student ${studentEmail}:`, error);
        if (error.name === 'ValidationException' && error.message.includes('specified index does not exist')) {
            console.error(`[MY_APPS_FATAL_ERROR] >>> The index "${correctIndexName}" was not found on table "${HIRING_APPLICATIONS_TABLE}". Please verify the index name in AWS DynamoDB. <<<`);
            if (!res.headersSent) {
                res.status(500).json({ message: `Configuration Error: The required database index ("${correctIndexName}") is missing. Please contact support.` });
            }
        } else if (!res.headersSent) {
            res.status(500).json({ message: 'Server error fetching your applications. Please try again later or contact support.' });
        } else {
             console.error("[MY_APPS_ERROR] Headers already sent, could not send error response.");
        }
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
            TableName: APPLICATIONS_TABLE_NAME, // <--- UPDATED TABLE
            Key: { applicationId }, // Assumes 'applicationId' is the Primary Key
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
        const { Items } = await docClient.send(new ScanCommand({
            TableName: APPLICATIONS_TABLE_NAME, // <--- UPDATED TABLE
            FilterExpression: "email = :email",
            ExpressionAttributeValues: { ":email": emailLower },
            Limit: 1
        }));

        if (!Items || Items.length === 0) {
            return res.status(404).json({ message: 'No applications found for this email address.' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expirationTime = Date.now() + 5 * 60 * 1000; // 5-minute validity

        otpStore[emailLower] = { otp, expirationTime };
        console.log(`Generated application view OTP for ${email}: ${otp}`);

        const mailOptions = {
            from: '"Xeta Solutions" <support@testify-lac.com>',
            to: email,
            subject: 'Your Application Status Verification Code',
            html: `<div style="
    font-family: 'Poppins', Arial, sans-serif;
    max-width: 480px;
    margin: auto;
    padding: 0;
    background: #f8fafc;
">

    <!-- Card -->
    <div style="
        background: #ffffff;
        padding: 32px;
        border-radius: 14px;
        border: 1px solid #e2e8f0;
        box-shadow: 0 4px 14px rgba(0,0,0,0.05);
        text-align: center;
    ">

        <!-- Logo -->
        <img 
            src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1760704788/XETA_SOLUTIONS_bt6bgn.jpg" 
            alt="Xeta Solutions Logo" 
            style="height: 48px; margin-bottom: 25px;"
        />

        <!-- Title -->
        <h2 style="color: #0f172a; font-weight: 600; margin-bottom: 8px; font-size: 22px;">
            Verification Code
        </h2>

        <p style="font-size: 15px; color: #475569; margin-top: 0;">
            Please use the code below to continue your verification.
        </p>

        <!-- OTP Box -->
        <div style="
            font-size: 34px;
            font-weight: 700;
            letter-spacing: 10px;
            color: #4F46E5;
            background: #eef2ff;
            padding: 16px 0;
            border-radius: 12px;
            margin: 28px 0;
            border: 1px solid #c7d2fe;
        ">
            ${otp}
        </div>

        <p style="font-size: 14px; color: #64748b; margin-top: 0;">
            This code is valid for the next <strong>5 minutes</strong>.
        </p>

        <p style="font-size: 13px; color: #94a3b8; margin-top: 22px;">
            If you did not request this code, please ignore this email.
        </p>
    </div>

    <!-- Footer -->
    <div style="
        text-align: center;
        color: #94a3b8;
        font-size: 12px;
        margin-top: 18px;
        padding: 16px 10px;
        line-height: 18px;
    ">
        <p style="margin: 4px 0; font-weight: 500; color: #64748b;">
            Xeta Solutions Pvt. Ltd.
        </p>
        <p style="margin: 4px 0;">
            Hyderabad, Telangana, India
        </p>
        <p style="margin: 4px 0;">
            This is an automated message. Please do not reply.
        </p>

        <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 12px auto; width: 70%;" />

        <p style="margin: 4px 0;">
            © ${new Date().getFullYear()} Xeta Solutions. All rights reserved.
        </p>

        <p style="margin: 4px 0;">
            <a href="https://www.testify-lac.com/T&C.html" style="color: #6366f1; text-decoration: none;">Privacy Policy</a> ·
            <a href="mailto:Support@xetasolutions.in" style="color: #6366f1; text-decoration: none;">Contact Support</a>
        </p>
    </div>

</div>
`
        };

       await sendEmailWithSES(mailOptions);
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

    const storedOtpData = otpStore[emailLower];
    if (!storedOtpData || storedOtpData.otp !== otp || Date.now() > storedOtpData.expirationTime) {
        return res.status(400).json({ message: 'Invalid or expired verification code.' });
    }

    try {
        delete otpStore[emailLower];

        const { Items: applications } = await docClient.send(new ScanCommand({
            TableName: APPLICATIONS_TABLE_NAME, // <--- UPDATED TABLE
            FilterExpression: "email = :email",
            ExpressionAttributeValues: { ":email": emailLower }
        }));

        if (!applications || applications.length === 0) {
            return res.json([]);
        }

        const jobIds = [...new Set(applications.map(app => app.jobId))];
        const keys = jobIds.map(jobId => ({ jobId: jobId }));
        
        if (keys.length === 0) {
             return res.json(applications);
        }

        const { Responses } = await docClient.send(new BatchGetCommand({
            RequestItems: { [CORRECT_JOBS_TABLE_NAME]: { Keys: keys } }
        }));
        
        const jobs = Responses[CORRECT_JOBS_TABLE_NAME] || [];
        const jobDeadlineMap = new Map(jobs.map(j => [j.jobId, j.applicationDeadline]));

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
app.get('/api/public/hiring-application/:applicationId', async (req, res) => {
    const { applicationId } = req.params;
    try {
        // 1. Fetch the application from the correct table, TestifyApplications
        const { Item: application } = await docClient.send(new GetCommand({
            TableName: "TestifyApplications",
            Key: { applicationId }
        }));

        if (!application) {
            return res.status(404).json({ message: "Application not found." });
        }

        // 2. Fetch the associated job to check the deadline and get the title
        const { Item: job } = await docClient.send(new GetCommand({
            TableName: "TestifyTests",
            Key: { testId: application.jobId } 
        }));

        if (!job) {
             return res.status(404).json({ message: "Associated job not found." });
        }
        
        // 3. Check if the deadline has passed (for display purposes on the frontend)
        const isEditable = new Date() < new Date(job.applicationDeadline);
        
        // 4. Send back the application data along with job title and editable status
        res.json({ ...application, jobTitle: job.title, isEditable });

    } catch (error) {
        console.error("Get Single Hiring Application Error:", error);
        res.status(500).json({ message: 'Server error fetching application.' });
    }
});

app.post('/api/hiring/coding-problems', hiringModeratorAuth, async (req, res) => {
    const { title, description, difficulty, score, inputFormat, outputFormat, constraints, example, testCases } = req.body;
    if (!title || !description || !difficulty || !score || !testCases || testCases.length === 0) {
        return res.status(400).json({ message: 'Missing required problem fields.' });
    }
    const problemId = `hire_problem_${uuidv4()}`;
    const newProblem = {
        problemId, title, description, difficulty, score: parseInt(score, 10), inputFormat, outputFormat, constraints, example, testCases,
        createdBy: req.user.email, createdAt: new Date().toISOString()
    };
    try {
        await docClient.send(new PutCommand({ TableName: HIRING_CODING_PROBLEMS_TABLE, Item: newProblem }));
        res.status(201).json({ message: 'Coding problem created successfully!', problem: { ...newProblem, id: problemId } }); // Map to id
    } catch (error) {
        console.error("Create Coding Problem Error:", error);
        res.status(500).json({ message: 'Server error creating problem.' });
    }
});

// Get all coding problems created by the hiring moderator
app.get('/api/hiring/coding-problems', hiringModeratorAuth, async (req, res) => {
    try {
        const { Items } = await docClient.send(new QueryCommand({
            TableName: HIRING_CODING_PROBLEMS_TABLE,
            IndexName: "createdBy-index",
            KeyConditionExpression: "createdBy = :creator",
            ExpressionAttributeValues: { ":creator": req.user.email }
        }));
        res.json((Items || []).map(p => ({ ...p, id: p.problemId }))); // Map problemId to id
    } catch (error) {
        console.error("Get Moderator Coding Problems Error:", error);
        res.status(500).json({ message: 'Server error fetching problems.' });
    }
});

app.put('/api/hiring/coding-problems/:problemId', authMiddleware, hiringModeratorAuth, async (req, res) => {
    const { problemId } = req.params;
    const { title, description, difficulty, score, inputFormat, outputFormat, constraints, example, testCases } = req.body;

    console.log(`[UPDATE PROBLEM] Request received for problemId: ${problemId} by ${req.user.email}`);

    // Basic validation
    if (!title || !description || !difficulty || score === undefined || !testCases || !Array.isArray(testCases) || testCases.length === 0) {
        console.warn(`[UPDATE PROBLEM] Validation failed for ${problemId}: Missing required fields.`);
        return res.status(400).json({ message: 'Missing required problem fields (title, description, difficulty, score, testCases).' });
    }
    const parsedScore = parseInt(score, 10);
    if (isNaN(parsedScore)) {
        console.warn(`[UPDATE PROBLEM] Validation failed for ${problemId}: Invalid score value.`);
        return res.status(400).json({ message: 'Score must be a valid number.' });
    }


    try {
        // 1. Verify the problem exists and belongs to the moderator
        console.log(`[UPDATE PROBLEM] Fetching existing problem ${problemId} from ${HIRING_CODING_PROBLEMS_TABLE}`);
        const { Item: existingProblem } = await docClient.send(new GetCommand({
            TableName: HIRING_CODING_PROBLEMS_TABLE,
            Key: { problemId } // Ensure 'problemId' is the correct primary key
        }));

        if (!existingProblem) {
            console.warn(`[UPDATE PROBLEM] Problem ${problemId} not found.`);
            return res.status(404).json({ message: 'Coding problem not found.' });
        }
        // Check ownership
        if (existingProblem.createdBy !== req.user.email) {
            console.warn(`[UPDATE PROBLEM] Permission denied for ${problemId}. Owner: ${existingProblem.createdBy}, Requester: ${req.user.email}`);
            return res.status(403).json({ message: 'You do not have permission to modify this problem.' });
        }
        console.log(`[UPDATE PROBLEM] Ownership verified for ${problemId}. Proceeding with update.`);

        // 2. Prepare the update command using UpdateCommand for robustness
        // Only updates fields that are actually sent in the request body
        const updateExpressionParts = [];
        const expressionAttributeNames = {};
        const expressionAttributeValues = {};

        // Helper to add field to update expression if it exists in the body
        const addUpdate = (key, attributeName, placeholder) => {
            if (req.body[key] !== undefined) {
                updateExpressionParts.push(`${attributeName} = ${placeholder}`);
                // Use ExpressionAttributeNames if the key is a reserved word (like 'constraints')
                if (attributeName.startsWith('#')) {
                    expressionAttributeNames[attributeName] = key;
                }
                // Assign value (handle score parsing)
                expressionAttributeValues[placeholder] = (key === 'score') ? parsedScore : req.body[key];
            }
        };

        addUpdate('title', ':t', ':titleValue'); // DynamoDB attribute name can be same as key if not reserved
        addUpdate('description', ':d', ':descValue');
        addUpdate('difficulty', ':diff', ':diffValue');
        addUpdate('score', ':s', ':scoreValue'); // Use parsedScore here
        addUpdate('inputFormat', ':if', ':ifValue');
        addUpdate('outputFormat', ':of', ':ofValue');
        addUpdate('constraints', '#const', ':constValue'); // Use # for potential reserved word
        addUpdate('example', ':e', ':exValue');
        addUpdate('testCases', ':tc', ':tcValue'); // Update the whole test case array

        // Check if any fields were actually provided for update
        if (updateExpressionParts.length === 0) {
            console.log(`[UPDATE PROBLEM] No fields provided to update for ${problemId}.`);
            return res.status(400).json({ message: 'No fields provided for update.' });
        }


        // Construct the final UpdateExpression
        const updateExpression = `SET ${updateExpressionParts.join(', ')}`;

        const updateParams = {
            TableName: HIRING_CODING_PROBLEMS_TABLE,
            Key: { problemId },
            UpdateExpression: updateExpression,
            ExpressionAttributeValues: expressionAttributeValues,
            ReturnValues: "UPDATED_NEW" // Optional: Return the updated item
        };
         // Add ExpressionAttributeNames only if needed (e.g., for 'constraints')
        if (Object.keys(expressionAttributeNames).length > 0) {
            updateParams.ExpressionAttributeNames = expressionAttributeNames;
        }

        console.log(`[UPDATE PROBLEM] Executing UpdateCommand for ${problemId}`);
        await docClient.send(new UpdateCommand(updateParams));

        console.log(`[UPDATE PROBLEM] Problem ${problemId} updated successfully.`);
        res.status(200).json({ message: 'Coding problem updated successfully!' });

    } catch (error) {
        console.error(`[UPDATE PROBLEM] Error updating problem ${problemId}:`, error);
        res.status(500).json({ message: 'Server error updating coding problem.' });
    }
});

// --- HIRING MODERATOR: CODING TEST MANAGEMENT ---
// NEW ENDPOINT TO FETCH HIRING TESTS (Aptitude or Coding)
app.get('/api/hiring/tests', hiringModeratorAuth, async (req, res) => {
    // Determine which type of test to fetch based on query param
    const typeQuery = req.query.type; // Expect 'coding' or undefined/other for aptitude
    let tableName;
    let pkName; // Primary key name for the specific table

    if (typeQuery === 'coding') {
        tableName = HIRING_CODING_TESTS_TABLE;
        pkName = 'codingTestId'; // Primary key of HiringCodingTests table
        console.log(`[GET /api/hiring/tests] Fetching CODING tests for moderator: ${req.user.email}`);
    } else {
        // --- CHANGE: Fetch from HIRING_APTITUDE_TESTS_TABLE ---
        tableName = HIRING_APTITUDE_TESTS_TABLE;
        pkName = 'aptitudeTestId'; // Primary key of HiringAptitudeTests table
        console.log(`[GET /api/hiring/tests] Fetching APTITUDE tests for moderator: ${req.user.email}`);
    }

    try {
        // Query the appropriate table using the createdBy index
        const { Items } = await docClient.send(new QueryCommand({
            TableName: tableName,
            IndexName: "createdBy-index", // Assumes this GSI exists on both tables with 'createdBy' as the HASH key
            KeyConditionExpression: "createdBy = :creator",
            ExpressionAttributeValues: { ":creator": req.user.email }
        }));

        console.log(`[GET /api/hiring/tests] Found ${Items ? Items.length : 0} tests of type '${typeQuery || 'aptitude'}'`);

        // Map the table-specific primary key (aptitudeTestId or codingTestId) to a common 'testId' for the frontend
        const tests = (Items || []).map(item => ({ ...item, testId: item[pkName] }));

        // Sort by creation date, newest first
        tests.sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt));

        res.json(tests);
    } catch (error) {
        console.error(`[GET /api/hiring/tests] Error fetching ${typeQuery || 'aptitude'} tests for ${req.user.email}:`, error);
        res.status(500).json({ message: `Server error fetching ${typeQuery || 'aptitude'} tests.` });
    }
});


// NOTE: This assumes a Global Secondary Index named createdBy-index exists on both the HiringJobs and HiringCodingTests tables with createdBy as the partition key.

// Create a new hiring coding test (which is a collection of problems)
app.post('/api/hiring/coding-tests', hiringModeratorAuth, async (req, res) => {
    // NEW: Destructure useSectionSettings and passingPercentage
    const { testTitle, duration, sections, useSectionSettings, passingPercentage } = req.body;
    console.log("[POST /api/hiring/coding-tests] Received payload:", req.body);

    if (!testTitle || typeof testTitle !== 'string' || testTitle.trim() === '') {
        return res.status(400).json({ message: 'Test Title is required.' });
    }
    if (!useSectionSettings && (isNaN(parseInt(duration, 10)) || parseInt(duration, 10) <= 0)) {
        return res.status(400).json({ message: 'Total Duration is required when section settings are disabled.' });
    }
    if (!sections || !Array.isArray(sections) || sections.length === 0) {
        return res.status(400).json({ message: 'At least one section is required.' });
    }

    let totalMarks = 0;
    const sectionsToStore = [];

    for (const [index, section] of sections.entries()) {
        if (!section.title || !section.problems || !Array.isArray(section.problems) || section.problems.length === 0) {
            return res.status(400).json({ message: `Section "${section.title || index + 1}" must have a title and at least one problem.` });
        }
        
        // NEW: Validate section-specific settings if enabled
        if (useSectionSettings) {
            if (!section.sectionTimer || section.sectionTimer <= 0) {
                return res.status(400).json({ message: `Please provide a valid timer for section: "${section.title}"` });
            }
            if (section.sectionQualifyingMarks === null || section.sectionQualifyingMarks === undefined || section.sectionQualifyingMarks < 0) {
                return res.status(400).json({ message: `Please provide valid qualifying marks (can be 0) for section: "${section.title}"` });
            }
        }

        const problemsToStore = section.problems.map(p => {
            const score = parseInt(p.score, 10) || 0;
            totalMarks += score;
            return {
                problemId: p.id || p.problemId,
                title: p.title,
                difficulty: p.difficulty,
                score: score
            };
        });
        
        sectionsToStore.push({
            title: section.title,
            problems: problemsToStore,
            sectionTimer: section.sectionTimer || null, // NEW: Save this
            sectionQualifyingMarks: section.sectionQualifyingMarks || 0 // NEW: Save this
        });
    }

    const codingTestId = `hire_coding_test_${uuidv4()}`;
    const newTest = {
        codingTestId,
        title: testTitle.trim(),
        duration: parseInt(duration, 10) || 0,
        passingPercentage: parseInt(passingPercentage, 10) || null, // NEW: Save this
        totalMarks,
        sections: sectionsToStore, // This now contains all data
        useSectionSettings: useSectionSettings || false, // NEW: Save this flag
        createdBy: req.user.email,
        createdAt: new Date().toISOString()
    };
    console.log("[POST /api/hiring/coding-tests] Saving new test:", newTest);

    try {
        await docClient.send(new PutCommand({ TableName: HIRING_CODING_TESTS_TABLE, Item: newTest }));
        res.status(201).json({ message: 'Coding test created successfully!', test: { ...newTest, testId: codingTestId } });
    } catch (error) {
        console.error("Create Coding Test Error:", error);
        res.status(500).json({ message: 'Server error creating test.' });
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
                from: '"TESTIFY" <support@testify-lac.com>',
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
                                Houston, TX, USA | <a href="mailto:support@testify-lac.com" style="color: #3b82f6; text-decoration: underline;">Contact Us</a>
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
           await sendEmailWithSES(mailOptions);
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
                from: '"TESTIFY" <support@testify-lac.com>',
                to: targetAttendees.join(','),
                subject: `Invitation: ${title}`,
                html: `<p>You have been invited to a meeting: <strong>${title}</strong>.</p><p>It is scheduled for ${new Date(startTime).toLocaleString()}. Please check your dashboard to join.</p>`
            };
           await sendEmailWithSES(mailOptions);
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


// Add these new endpoints to your backend.js file

// ADMIN: Get all test results for managing previews
app.get('/api/admin/all-test-results', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    try {
        const { Items: results } = await docClient.send(new ScanCommand({
            TableName: "TestifyResults"
        }));

        if (!results || results.length === 0) {
            return res.json([]);
        }
        
        // To avoid fetching user details one-by-one, get all unique emails and fetch in a batch
        const studentEmails = [...new Set(results.map(r => r.studentEmail))];
        const userKeys = studentEmails.map(email => ({ email }));

        const { Responses } = await docClient.send(new BatchGetCommand({
            RequestItems: {
                "TestifyUsers": {
                    Keys: userKeys,
                    ProjectionExpression: "email, fullName"
                }
            }
        }));

        const userMap = new Map((Responses.TestifyUsers || []).map(user => [user.email, user.fullName]));

        const enrichedResults = results.map(result => ({
            ...result,
            studentName: userMap.get(result.studentEmail) || result.studentEmail // Fallback to email if name not found
        }));

        enrichedResults.sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt));
        
        res.json(enrichedResults);

    } catch (error) {
        console.error("Get All Test Results Error:", error);
        res.status(500).json({ message: 'Server error fetching all test results.' });
    }
});


// ADMIN: Update permission for a student to view a test preview
app.post('/api/admin/update-preview-permission', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { resultId, allowPreview } = req.body;
    if (!resultId || typeof allowPreview !== 'boolean') {
        return res.status(400).json({ message: 'Result ID and permission status are required.' });
    }

    try {
        await docClient.send(new UpdateCommand({
            TableName: "TestifyResults",
            Key: { resultId },
            UpdateExpression: "set allowPreview = :val",
            ExpressionAttributeValues: {
                ":val": allowPreview
            }
        }));
        res.status(200).json({ message: 'Preview permission updated successfully.' });
    } catch (error) {
        console.error("Update Preview Permission Error:", error);
        res.status(500).json({ message: 'Server error updating permission.' });
    }
});


// STUDENT: Get detailed test preview if permission is granted
app.get('/api/student/test-preview/:resultId', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Student') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { resultId } = req.params;
    const studentEmail = req.user.email;

    try {
        // 1. Fetch the student's result
        const { Item: result } = await docClient.send(new GetCommand({
            TableName: "TestifyResults",
            Key: { resultId }
        }));

        // 2. Security checks
        if (!result) {
            return res.status(404).json({ message: 'Test result not found.' });
        }
        if (result.studentEmail !== studentEmail) {
            return res.status(403).json({ message: 'You are not authorized to view this result.' });
        }
        if (result.allowPreview !== true) {
            return res.status(403).json({ message: 'Preview for this test has not been enabled by the administrator.' });
        }

        // FIX: Add logic to handle both static and dynamic tests for preview
        let test;
        // 3. Check for embedded static test data first
        if (result.staticTestData) {
            test = result.staticTestData;
        } else {
            // 4. If not found, fetch from the original TestifyTests table
            const { Item } = await docClient.send(new GetCommand({
                TableName: "TestifyTests",
                Key: { testId: result.testId }
            }));
            test = Item;
        }

        if (!test) {
            return res.status(404).json({ message: 'Original test content not found.' });
        }
        
        // 5. Combine and send the data
        res.json({
            testTitle: test.title,
            questions: test.questions, // Contains questions, options, and correct answers
            studentAnswers: result.answers // The student's submitted answers
        });

    } catch (error) {
        console.error("Get Test Preview Error:", error);
        res.status(500).json({ message: 'Server error fetching test preview.' });
    }
});
// const authMiddleware = async (req, res, next) => {
//     const token = req.header('x-auth-token');
//     if (!token) {
//         return res.status(401).json({ message: 'No token, authorization denied' });
//     }
//     try {
//         const decoded = jwt.verify(token, JWT_SECRET);
//         req.user = decoded.user;

//         // For internal users, verify they exist and are not blocked.
//         // For external hiring candidates (isExternal: true), this check is skipped.
//         if (!req.user.isExternal) {
//             const { Item } = await docClient.send(new GetCommand({
//                 TableName: "TestifyUsers",
//                 Key: { email: req.user.email }
//             }));

//             if (!Item) {
//                 return res.status(404).json({ message: 'User not found.' });
//             }

//             if (Item.isBlocked) {
//                 return res.status(403).json({ message: 'Your account has been blocked by the administrator.' });
//             }

//             if (Item.role === 'Moderator') {
//                 req.user.assignedColleges = Item.assignedColleges || [];
//             }
//         }

//         next(); // Allows the request to proceed for all valid tokens.
//     } catch (e) {
//         res.status(401).json({ message: 'Token is not valid' });
//     }
// };
// =================================================================
// --- HIRE WITH US FEATURE ENDPOINTS ---
// =================================================================

// ADMIN: Create a new Hiring Moderator
app.post('/api/admin/hiring-moderators', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }

    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) {
        return res.status(400).json({ message: 'Please provide full name, email, and password.' });
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
            role: "Hiring Moderator", // New Role
            isBlocked: false
        };

        await docClient.send(new PutCommand({ TableName: "TestifyUsers", Item: newModerator }));
        res.status(201).json({ message: 'Hiring Moderator account created successfully!' });
    } catch (error) {
        console.error("Create Hiring Moderator Error:", error);
        res.status(500).json({ message: 'Server error during hiring moderator creation.' });
    }
});

// HIRING MODERATOR: Create a new Test
app.post('/api/hiring/tests', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Hiring Moderator' && req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }

    // NEW: Destructure useSectionSettings and check new section fields
    const { testTitle, duration, totalMarks, passingPercentage, sections, useSectionSettings } = req.body;
    const aptitudeTestId = `hire_apt_${uuidv4()}`;

    // Validate section-specific settings if enabled
    if (useSectionSettings) {
        if (!sections || sections.some(s => !s.sectionTimer || s.sectionQualifyingMarks === undefined || s.sectionQualifyingMarks === null)) {
            return res.status(400).json({ message: 'When section-specific settings are enabled, every section must have a timer and qualifying marks (can be 0).' });
        }
    }

    const newTest = {
        aptitudeTestId,
        title: testTitle,
        duration: parseInt(duration, 10),
        totalMarks: parseInt(totalMarks, 10),
        passingPercentage: parseInt(passingPercentage, 10),
        sections, // This now contains { title, questions, sectionTimer, sectionQualifyingMarks }
        useSectionSettings: useSectionSettings || false, // NEW: Save this flag
        createdBy: req.user.email,
        createdAt: new Date().toISOString()
    };

    try {
        await docClient.send(new PutCommand({ TableName: HIRING_APTITUDE_TESTS_TABLE, Item: newTest }));
        res.status(201).json({ message: 'Hiring aptitude test created successfully!', test: { ...newTest, testId: aptitudeTestId } });
    } catch (error) {
        console.error("Create Hiring Aptitude Test Error:", error);
        res.status(500).json({ message: 'Server error creating hiring aptitude test.' });
    }
});


// --- 2. UPDATE: Update Aptitude Test Endpoint ---
// Find: app.put('/api/hiring/aptitude-tests/:aptitudeTestId', ...)
// REPLACE the entire endpoint with this updated version:

app.put('/api/hiring/aptitude-tests/:aptitudeTestId', hiringModeratorAuth, async (req, res) => {
    const { aptitudeTestId } = req.params;
    // NEW: Destructure useSectionSettings and check new section fields
    const { testTitle, duration, totalMarks, passingPercentage, sections, useSectionSettings } = req.body;

    if (!testTitle || !duration || !totalMarks || !passingPercentage || !sections) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    // Validate section-specific settings if enabled
    if (useSectionSettings) {
        if (!sections || sections.some(s => !s.sectionTimer || !s.sectionQualifyingMarks)) {
            return res.status(400).json({ message: 'When section-specific settings are enabled, every section must have a timer and qualifying marks.' });
        }
    }

    try {
        const { Item: existingTest } = await docClient.send(new GetCommand({
            TableName: HIRING_APTITUDE_TESTS_TABLE,
            Key: { aptitudeTestId }
        }));
        if (!existingTest || existingTest.createdBy !== req.user.email) {
            return res.status(403).json({ message: 'Access denied.' });
        }

        const updatedTest = {
            ...existingTest,
            title: testTitle,
            duration: parseInt(duration, 10),
            totalMarks: parseInt(totalMarks, 10),
            passingPercentage: parseInt(passingPercentage, 10),
            sections, // This now contains { title, questions, sectionTimer, sectionQualifyingMarks }
            useSectionSettings: useSectionSettings || false, // NEW: Save this flag
            updatedAt: new Date().toISOString()
        };

        await docClient.send(new PutCommand({
            TableName: HIRING_APTITUDE_TESTS_TABLE,
            Item: updatedTest
        }));
        
        res.status(200).json({ message: 'Aptitude test updated successfully!', test: updatedTest });
    } catch (error) {
        console.error("Update Aptitude Test Error:", error);
        res.status(500).json({ message: 'Server error updating aptitude test.' });
    }
});


// NEW ENDPOINT TO FETCH HIRING TESTS
app.get('/api/hiring/tests', hiringModeratorAuth, async (req, res) => {
    const typeQuery = req.query.type;
    let tableName;
    let pkName;
    if (typeQuery === 'coding') {
        tableName = HIRING_CODING_TESTS_TABLE;
        pkName = 'codingTestId';
    } else {
        tableName = HIRING_JOBS_TABLE; // Default to Aptitude/Jobs
        pkName = 'jobId';
    }
    try {
        const { Items } = await docClient.send(new QueryCommand({
            TableName: tableName,
            IndexName: "createdBy-index",
            KeyConditionExpression: "createdBy = :creator",
            ExpressionAttributeValues: { ":creator": req.user.email }
        }));
         const tests = (Items || []).map(item => ({ ...item, testId: item[pkName] })); // Map PK to testId
         tests.sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt));
        res.json(tests);
    } catch (error) {
        console.error(`Get Hiring ${typeQuery || 'Aptitude'} Tests Error:`, error);
        res.status(500).json({ message: `Server error fetching ${typeQuery || 'aptitude'} tests.` });
    }
});

// // --- Add near the top with other table constants ---
// const HIRING_USERS_TABLE = "HiringUsers"; // Assuming this exists for moderator lookups if needed
// const HIRING_COLLEGES_TABLE = "HiringColleges"; // Assuming this exists
// const HIRING_JOBS_TABLE = "HiringJobs";                 // Aptitude tests / Job postings
// const HIRING_APPLICATIONS_TABLE = "HiringApplications"; // Applications for HIRING_JOBS_TABLE items
// const HIRING_CODING_PROBLEMS_TABLE = "HiringCodingProblems";
// const HIRING_CODING_TESTS_TABLE = "HiringCodingTests";
// const HIRING_ASSIGNMENTS_TABLE = "HiringAssignments";   // Assignments for both types
// const HIRING_TEST_RESULTS_TABLE = "HiringTestResults";   // Results for both types
// const HIRING_CODE_SNIPPETS_TABLE = "HiringCodeSnippets"; // For code snippets

// // Ensure necessary imports are present:
// // authMiddleware, docClient, GetCommand, PutCommand, QueryCommand, uuidv4, ScanCommand (optional fallback)

// /**
//  * @route   POST /api/public/submit-coding-test
//  * @desc    External Candidate: Submits final answers for a coding test.
//  * @access  Private (External Candidate Token Required)
//  */
// Assuming docClient and HIRING_CODE_SNIPPETS_TABLE are defined elsewhere
// Assuming authMiddleware is correctly populating req.user

app.post('/api/public/submit-coding-test', authMiddleware, async (req, res) => {
    if (!req.user || !req.user.isExternal) {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { testId: testPkFromToken, email: candidateEmail, assignmentId } = req.user;
    const { submissions, violationReason, candidateDetails } = req.body;

    if (!candidateDetails || !candidateDetails.fullName /*... other details ...*/) {
        return res.status(400).json({ message: 'Missing required candidate details.' });
    }
    if (!Array.isArray(submissions)) {
        return res.status(400).json({ message: "Invalid submission data format." });
    }

    const resultId = `hcs_${uuidv4()}`;

    try {
        // --- 1. Verify Assignment Record ---
        const { Item: assignment } = await docClient.send(new GetCommand({
            TableName: HIRING_ASSIGNMENTS_TABLE, Key: { assignmentId }
        }));
        if (!assignment || assignment.studentEmail !== candidateEmail || assignment.testId !== testPkFromToken || assignment.testType !== 'coding') {
            return res.status(403).json({ message: 'Assignment validation failed.' });
        }
        
        const jobId = assignment.jobId || null;

        // --- 2. Check for Previous *SUBMITTED* Submission ---
       const { Items: existingSubmittedResults } = await docClient.send(new QueryCommand({
           TableName: HIRING_TEST_RESULTS_TABLE, IndexName: 'AssignmentIdIndex',
           KeyConditionExpression: 'assignmentId = :aid',
           FilterExpression: 'attribute_not_exists(resultId) OR not begins_with(resultId, :initPrefix)',
           ExpressionAttributeValues: { ':aid': assignmentId, ':initPrefix': 'init_' }, Limit: 1
       }));
       if (existingSubmittedResults && existingSubmittedResults.length > 0) {
            return res.status(409).json({ message: 'This test has already been submitted.' });
       }

        // --- 3. Fetch Coding Test Definition ---
        const { Item: test } = await docClient.send(new GetCommand({
            TableName: HIRING_CODING_TESTS_TABLE,
            Key: { codingTestId: assignment.testId } 
        }));

        if (!test || (!Array.isArray(test.sections) && !Array.isArray(test.problems))) {
            return res.status(404).json({ message: "Coding test definition not found or invalid." });
        }

        // --- 4. Create Problem Map for Scoring ---
        const problemMapForScores = new Map();
        let totalPossibleMarks = 0;

        if (test.sections && Array.isArray(test.sections)) {
            test.sections.forEach(section => {
                section.problems.forEach(p => {
                    const score = parseInt(p.score, 10) || 0;
                    problemMapForScores.set(p.problemId, { score: score, title: p.title, sectionTitle: section.title });
                    totalPossibleMarks += score;
                });
            });
        } else if (test.problems && Array.isArray(test.problems)) {
            // Backwards compatibility
            test.problems.forEach(p => {
                 const score = parseInt(p.score, 10) || 0;
                 problemMapForScores.set(p.problemId, { score: score, title: p.title, sectionTitle: "Coding Problems" });
                 totalPossibleMarks += score;
            });
        }
        if (test.totalMarks && parseInt(test.totalMarks, 10) > 0) {
             totalPossibleMarks = parseInt(test.totalMarks, 10);
        }

        // --- 5. Process Submissions & Calculate Score ---
        let totalScore = 0;
        const detailedSubmissions = submissions.map(sub => {
            const problemId = sub.problemId;
            const problemInfo = problemMapForScores.get(problemId);
            const maxProblemScore = problemInfo ? problemInfo.score : 0;
            const problemTitle = problemInfo ? problemInfo.title : 'Title Not Found';
            const sectionTitle = problemInfo ? problemInfo.sectionTitle : 'Unknown Section';

            const evaluationResults = sub.evaluationResults || [];
            const passedCases = evaluationResults.filter(r => r?.status === 'Accepted').length;
            const totalCases = evaluationResults.length;

            const calculatedScore = (totalCases > 0 && maxProblemScore > 0)
                                      ? Math.round((passedCases / totalCases) * maxProblemScore)
                                      : 0;
            totalScore += calculatedScore;

            return {
                 problemId: problemId,
                 problemTitle: problemTitle,
                 sectionTitle: sectionTitle,
                 language: sub.language || 'N/A',
                 code: sub.code || '',
                 score: maxProblemScore, // Max possible score
                 calculatedScore: calculatedScore, // Actual score
                 passedCases: passedCases,
                 totalCases: totalCases,
                 evaluationResults: evaluationResults
             };
        });

        // --- 6. Construct Final Result Object ---
        const newSubmissionResult = {
            resultId,
            testId: assignment.testId,
            assignmentId,
            jobId: jobId,
            testType: 'coding',
            candidateEmail,
            fullName: candidateDetails.fullName,
            rollNumber: candidateDetails.rollNumber,
            collegeName: candidateDetails.collegeName,
            department: candidateDetails.department,
            profileImageUrl: candidateDetails.profileImageUrl || null,
            testTitle: test.title || 'N/A',
            submissions: detailedSubmissions,
            score: totalScore,
            totalMarks: totalPossibleMarks,
            result: (totalPossibleMarks > 0 && (totalScore / totalPossibleMarks) * 100 >= (test.passingPercentage || 50)) ? "Pass" : "Fail", 
            submittedAt: new Date().toISOString(),
            violationReason: violationReason || null,
            sectionScores: test.sections ? test.sections.map(section => {
                let sectionTotalScore = 0;
                let sectionMaxScore = 0;
                detailedSubmissions.forEach(sub => {
                    if (sub.sectionTitle === section.title) {
                        sectionTotalScore += sub.calculatedScore;
                        sectionMaxScore += sub.score;
                    }
                });
                return { title: section.title, score: sectionTotalScore, maxScore: sectionMaxScore };
            }) : null
        };

        // --- 7. Save Result ---
        await docClient.send(new PutCommand({
            TableName: HIRING_TEST_RESULTS_TABLE,
            Item: newSubmissionResult
        }));
        
        res.status(201).json({ message: 'Test submitted successfully! Redirecting...' });

    } catch (error) {
        console.error(`[SUBMIT CODING TEST] FATAL ERROR processing assignment ${assignmentId}:`, error);
        res.status(500).json({ message: 'Server error submitting test. Please contact support.' });
    }
});
app.post('/api/public/upload-image', async (req, res) => {
    const { imageData } = req.body;
    if (!imageData) {
        return res.status(400).json({ message: 'No image data provided.' });
    }
    try {
        const result = await cloudinary.uploader.upload(imageData, {
            folder: "hiring_test_captures" // Store in a specific folder
        });
        res.json({ imageUrl: result.secure_url });
    } catch (error) {
        console.error("Public Image Upload Error:", error);
        res.status(500).json({ message: 'Server error uploading image.' });
    }
});

app.post('/api/hiring/coding-tests', hiringModeratorAuth, async (req, res) => {
    // Expect `sections` array instead of `problems`
    // sections = [{ title: "Section A", problems: [{ id/problemId, title, difficulty, score }, ...] }, ...]
    const { testTitle, duration, sections } = req.body;
    console.log("[POST /api/hiring/coding-tests] Received payload:", { testTitle, duration, sections }); // Log received data

    // --- Stricter Validation ---
    if (!testTitle || typeof testTitle !== 'string' || testTitle.trim() === '') {
        console.warn("[POST /api/hiring/coding-tests] Validation failed: Invalid or missing testTitle.");
        return res.status(400).json({ message: 'Test Title is required and cannot be empty.' });
    }

    const parsedDuration = parseInt(duration, 10);
    if (isNaN(parsedDuration) || parsedDuration <= 0) {
        console.warn(`[POST /api/hiring/coding-tests] Validation failed: Invalid duration value '${duration}'. Must be a positive number.`);
        return res.status(400).json({ message: 'Duration is required and must be a positive number of minutes.' });
    }

    if (!sections || !Array.isArray(sections) || sections.length === 0) {
        console.warn("[POST /api/hiring/coding-tests] Validation failed: Sections array is missing, empty, or not an array.");
        return res.status(400).json({ message: 'At least one section with problems is required.' });
    }
    // --- End Stricter Validation ---


    let totalMarks = 0;
    const sectionsToStore = [];

    // Validate and process sections
    for (const [index, section] of sections.entries()) { // Added index for better logging
        if (!section.title || typeof section.title !== 'string' || section.title.trim() === '') {
             console.warn(`[POST /api/hiring/coding-tests] Validation failed: Section ${index + 1} has an invalid or missing title.`);
             return res.status(400).json({ message: `Section ${index + 1} must have a non-empty title.` });
        }
        if (!section.problems || !Array.isArray(section.problems) || section.problems.length === 0) {
            console.warn(`[POST /api/hiring/coding-tests] Validation failed: Section '${section.title}' (Index ${index + 1}) has no problems.`);
            return res.status(400).json({ message: `Section "${section.title}" must contain at least one problem.` });
        }

        const problemsToStore = [];
        for (const p of section.problems) {
            const problemId = p.id || p.problemId;
            const score = parseInt(p.score, 10); // Use parseInt for score as well

            // Add basic validation for problems within the section
            if (!problemId || !p.title || !p.difficulty || isNaN(score) || score < 0) {
                console.warn(`[POST /api/hiring/coding-tests] Validation failed: Invalid problem data in section '${section.title}'. Problem:`, p);
                return res.status(400).json({ message: `Invalid problem data found in section "${section.title}". Ensure ID, title, difficulty, and a non-negative score are present.` });
            }

            totalMarks += score; // Accumulate total marks
            problemsToStore.push({
                problemId: problemId,
                title: p.title,
                difficulty: p.difficulty,
                score: score // Store the parsed score
            });
        }
        sectionsToStore.push({
            title: section.title,
            problems: problemsToStore
        });
    }

    const codingTestId = `hire_coding_test_${uuidv4()}`;
    const newTest = {
        codingTestId,
        title: testTitle.trim(), // Trim title
        duration: parsedDuration, // Use parsed duration
        totalMarks, // Calculated total marks
        sections: sectionsToStore, // Store the structured sections
        createdBy: req.user.email,
        createdAt: new Date().toISOString()
    };
    console.log("[POST /api/hiring/coding-tests] Saving new test:", newTest); // Log data being saved

    try {
        await docClient.send(new PutCommand({ TableName: HIRING_CODING_TESTS_TABLE, Item: newTest }));
        res.status(201).json({ message: 'Coding test created successfully!', test: { ...newTest, testId: codingTestId } }); // Map back if needed
    } catch (error) {
        console.error("Create Coding Test Error:", error);
        res.status(500).json({ message: 'Server error creating test.' });
    }
});


// HIRING: Assign a test to external candidates
app.post('/api/hiring/assign-test', hiringModeratorAuth, async (req, res) => {
    // *** NEW: Read jobId from the request body ***
    const { testId, candidateEmails, startTime, endTime, jobId } = req.body; 
    
    // --- Validation ---
    if (!testId || !candidateEmails || candidateEmails.length === 0 || !startTime || !endTime) {
         return res.status(400).json({ message: 'Missing required fields (testId, emails, startTime, endTime).' });
    }
    // *** NEW: JobID is optional for old tests, but required for new job-based flow ***
    if (!jobId) {
         console.warn("[ASSIGN TEST] Warning: Assigning test without a JobID. This may be legacy behavior.");
         // You could choose to make this an error:
         // return res.status(400).json({ message: 'A JobID is required to assign this test.' });
    }
    if (new Date(startTime) >= new Date(endTime)) {
         return res.status(400).json({ message: 'Start time must be before end time.' });
    }

    try {
        // --- Determine Test Type (Aptitude or Coding) ---
        let test;
        let testType = '';
        let testPk;
        let testTitle;

        const { Item: aptitudeTest } = await docClient.send(new GetCommand({
            TableName: HIRING_APTITUDE_TESTS_TABLE, Key: { aptitudeTestId: testId }
        }));

        if (aptitudeTest) {
            test = aptitudeTest;
            testType = 'aptitude';
            testPk = aptitudeTest.aptitudeTestId;
            testTitle = aptitudeTest.title;
        } else {
            const { Item: codingTest } = await docClient.send(new GetCommand({
                TableName: HIRING_CODING_TESTS_TABLE, Key: { codingTestId: testId }
            }));
            if (codingTest) {
                test = codingTest;
                testType = 'coding';
                testPk = codingTest.codingTestId;
                testTitle = codingTest.title;
            }
        }

        if (!test) {
            return res.status(404).json({ message: "Test not found." });
        }

        const baseUrl = req.protocol + '://' + req.get('host');
        const pageName = 'download-test-app.html';

        let assignmentsCreated = 0;
        for (const email of candidateEmails) {
            const assignmentId = uuidv4();
            const payload = { user: { email, testId: testPk, assignmentId, isExternal: true } };
            const testToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
            const testLink = `${baseUrl}/${pageName}?token=${testToken}`;

            // --- SAVE ASSIGNMENT with jobId ---
            await docClient.send(new PutCommand({
                TableName: HIRING_ASSIGNMENTS_TABLE,
                Item: {
                    assignmentId,
                    testId: testPk,
                    testType: testType,
                    // *** NEW: Save the JobID with the assignment ***
                    jobId: jobId || null, // Save jobId if provided
                    studentEmail: email,
                    assignedBy: req.user.email,
                    startTime, 
                    endTime, 
                    testToken,
                    assignedAt: new Date().toISOString()
                }
            }));

            // --- Send Email (copy-pasted from your original endpoint) ---
            const mailOptions = {
                 from: '"HIRE WITH US" <support@testify-lac.com>',
                 to: email,
                 subject: `Invitation to take ${testType} Test: ${testTitle}`,
                 html: `<!DOCTYPE html>
<html lang="en" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="x-apple-disable-message-reformatting">
    <title>HireWithUs Test Invitation</title>
    <!--[if mso]>
    <style>
        table, td, th, h1, h2, h3, p, a {font-family: 'Inter', Arial, sans-serif !important;}
        table {border-collapse: collapse !important;}
        .external-class * {line-height: 100%;}
    </style>
    <![endif]-->
    
    <!-- 
      This <style> block is ONLY for progressive enhancement.
      It will be ignored by Gmail/Outlook but read by Apple Mail, iOS, etc.
      It contains responsive styles and hover effects.
    -->
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');

        body {
            font-family: 'Inter', Roboto, 'Helvetica Neue', Arial, sans-serif;
        }

        @media screen and (max-width: 600px) {
            .container {
                width: 100% !important;
                border-radius: 0 !important;
                border-left: 0 !important;
                border-right: 0 !important;
            }
            .content-cell {
                padding: 25px !important;
            }
            .header-cell {
                padding: 30px 25px !important;
            }
            .step-icon {
                width: 40px !important;
                height: 40px !important;
            }
            .social-icon {
                padding: 0 8px !important;
            }
        }
        
        /* Button hover effect for compatible clients */
        .btn:hover {
            background: linear-gradient(135deg, #6d28d9, #3b82f6) !important;
            box-shadow: 0 10px 20px rgba(0,0,0,0.1) !important;
            transform: translateY(-2px) !important;
        }

        .footer-link:hover {
            text-decoration: underline !important;
        }
    </style>
</head>
<body style="margin: 0; padding: 0; background-color: #f3f4f6; width: 100%; font-family: 'Inter', Roboto, 'Helvetica Neue', Arial, sans-serif;">
    <table width="100%" border="0" cellpadding="0" cellspacing="0" bgcolor="#f3f4f6" style="background-color: #f3f4f6; margin: 0; padding: 0; width: 100%;">
        <tr>
            <td align="center" style="padding: 40px 10px;">
                
                <!--[if mso | IE]>
                <table align="center" border="0" cellpadding="0" cellspacing="0" width="600">
                <tr>
                <td style="width: 600px;">
                <![endif]-->

                <table class="container" border="0" cellpadding="0" cellspacing="0" width="600" style="background-color: #ffffff; width: 100%; max-width: 600px; margin: 0 auto; border-radius: 12px; border-collapse: separate; overflow: hidden; border: 1px solid #e5e7eb;">
                    
                    <!-- 🧠 Header Section -->
                    <tr>
                        <td class="header-cell" align="center" bgcolor="#2563eb" style="background: linear-gradient(135deg, #2563eb, #3b82f6); color: #ffffff; padding: 40px 30px; text-align: center;">
                            <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1760086493/HireWithUS_wtn0pc.png" alt="HireWithUs Logo" width="60" style="width: 60px; height: auto; margin-bottom: 16px; border: 0;">
                            <h1 style="margin: 0 0 8px; color: #ffffff; font-family: 'Inter', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 24px; font-weight: 700;">
                                Invitation to Test - HireWithUs
                            </h1>
                            <p style="margin: 0; color: #dbeafe; font-family: 'Inter', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 16px; font-weight: 400;">
                                Your Secure & Fair Assessment Awaits!
                            </p>
                        </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                        <td class="content-cell" style="padding: 35px 40px; color: #374151; line-height: 1.7; font-size: 16px; font-family: 'Inter', Roboto, 'Helvetica Neue', Arial, sans-serif;">
                            <p style="margin: 0 0 20px; font-size: 18px; line-height: 1.6;"><b style="color: #111827;">Hello,</b></p>
                            <p style="margin: 0 0 20px; font-size: 16px; line-height: 1.6;">
                                You have been invited to take the <strong style="color: #111827;">${testType === 'coding' ? 'Coding' : 'Aptitude'}</strong> test for the role of "<strong style="color: #111827;">${testTitle}</strong>".
                            </p>
                            
                            <!-- Test Window -->
                            <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #eff6ff; border-left: 4px solid #3b82f6; border-radius: 8px; margin: 24px 0;">
                                <tr>
                                    <td style="padding: 20px 24px;">
                                        <strong style="color: #1e40af; display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">Your Test Window:</strong>
                                        <p style="margin: 0 0 4px; color: #1d4ed8; font-size: 15px; line-height: 1.5; font-weight: 600;">
                                            <strong>Starts:</strong> ${new Date(startTime).toLocaleString()}
                                        </p>
                                        <p style="margin: 0; color: #1d4ed8; font-size: 15px; line-height: 1.5; font-weight: 600;">
                                            <strong>Ends:</strong> ${new Date(endTime).toLocaleString()}
                                        </p>
                                        <p style="margin: 12px 0 0; color: #1e40af; font-size: 14px; line-height: 1.5;">You can take the test at any time within this window.</p>
                                    </td>
                                </tr>
                            </table>

                            <!-- Section Divider -->
                            <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="margin: 30px 0;">
                                <tr>
                                    <td style="border-bottom: 1px solid #e5e7eb;"></td>
                                </tr>
                            </table>

                            <!-- 🧩 Step 1: Before the Test (Setup) -->
                            <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="margin-bottom: 24px;">
                                <tr>
                                    <td style="padding: 24px; background-color: #f9fafb; border-radius: 8px; border: 1px solid #f3f4f6;">
                                        <h3 style="margin: 0 0 20px; color: #1f2937; font-family: 'Inter', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 20px; font-weight: 600;">
                                            Step 1: Before the Test (Setup)
                                        </h3>
                                        
                                        <!-- Item 1 -->
                                        <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="margin-bottom: 16px;">
                                            <tr>
                                                <td style="font-size: 15px; color: #4b5563; line-height: 1.6;">
                                                    <strong>Download the App:</strong> This test requires our secure desktop application. Please click the button below to download it.
                                                </td>
                                            </tr>
                                        </table>
                                        <!-- Item 2 -->
                                        <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="margin-bottom: 16px;">
                                            <tr>
                                                <td style="font-size: 15px; color: #4b5563; line-height: 1.6;">
                                                    <strong>Run System Check:</strong> Install and run the app *at least one hour* before you plan to take the test. Use the "System Check" feature. This is mandatory.
                                                </td>
                                            </tr>
                                        </table>
                                        <!-- Item 3 -->
                                        <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="margin-bottom: 16px;">
                                            <tr>
                                                <td style="font-size: 15px; color: #4b5563; line-height: 1.6;">
                                                    <strong>Find Your Token:</strong> The download page will display a unique <strong>Access Token</strong>. Copy and save it securely. You will need it to log in.
                                                </td>
                                            </tr>
                                        </table>
                                        <!-- Item 4 -->
                                        <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation">
                                            <tr>
                                                <td style="font-size: 15px; color: #4b5563; line-height: 1.6;">
                                                    <strong>Prepare Your Environment:</strong> Use a Windows or macOS computer with a stable internet connection, a functional webcam, and a microphone.
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>

                            <!-- Download Button -->
                            <table width="100%" border="0" cellspacing="0" cellpadding="0" style="margin: 10px 0 30px; text-align: center;">
                                <tr>
                                    <td align="center">
                                        <!--[if mso]>
                                        <v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word" href="${testLink}" style="height:52px;v-text-anchor:middle;width:300px;" arcsize="16%" strokecolor="#3b82f6" fill="t">
                                            <v:fill type="gradient" color="#3b82f6" color2="#6d28d9" angle="135" />
                                            <w:anchorlock/>
                                            <center style="color:#ffffff;font-family: 'Inter', Arial, sans-serif;font-size:16px;font-weight:bold;">
                                                Download App & Get Token
                                            </center>
                                        </v:roundrect>
                                        <![endif]-->
                                        <!--[if !mso]><!-->
                                        <a href="${testLink}" target="_blank" class="btn" style="background: linear-gradient(135deg, #3b82f6, #6d28d9); color: #ffffff; padding: 16px 32px; text-decoration: none; border-radius: 8px; font-weight: 700; display: inline-block; font-family: 'Inter', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 16px; min-width: 250px; text-align: center; box-shadow: 0 4px 12px rgba(0,0,0,0.05); transition: all 0.2s ease;">
                                            Download App & Get Token
                                        </a>
                                        <!--<![endif]-->
                                    </td>
                                </tr>
                            </table>

                            <!-- 🛡️ Step 2: Zero-Tolerance Malpractice Policy -->
                            <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #fef2f2; border-left: 4px solid #ef4444; border-radius: 8px; margin: 24px 0; box-shadow: 0 4px 12px rgba(239,68,68,0.05);">
                                <tr>
                                    <td style="padding: 24px;">
                                        <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation">
                                            <tr>
                                                <td valign="top">
                                                    <h3 style="margin: 0 0 4px; color: #991b1b; font-family: 'Inter', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 20px; font-weight: 600;">
                                                        Step 2: Zero-Tolerance Malpractice Policy
                                                    </h3>
                                                    <p style="margin: 0 0 16px; font-size: 15px; color: #b91c1c; font-weight: 600;">
                                                        Integrity is our priority — one attempt, one opportunity.
                                                    </p>
                                                </td>
                                            </tr>
                                        </table>
                                        
                                        <p style="margin: 0 0 16px; font-size: 15px; color: #b91c1c; line-height: 1.6;">
                                            This is a proctored assessment. Your webcam, microphone, and screen will be monitored.
                                            Any violation of these rules will result in <strong style="color: #991b1b;">immediate disqualification</strong>.
                                        </p>
                                        <ul style="margin: 0; padding-left: 20px; font-size: 15px; line-height: 1.6; color: #b91c1c;">
                                            <li style="margin-bottom: 8px;"><strong>NO</strong> other people allowed in the room.</li>
                                            <li style="margin-bottom: 8px;"><strong>NO</strong> mobile phones, smart watches, or other devices.</li>
                                            <li style="margin-bottom: 8px;"><strong>DO NOT</strong> open new browser tabs, applications, or developer tools.</li>
                                            <li style="margin-bottom: 8px;"><strong>DO NOT</strong> copy/paste problem statements or code from external sources.</li>
                                            <li style="margin-bottom: 0;"><strong>DO NOT</strong> leave your seat or look away from the screen for extended periods.</li>
                                        </ul>
                                        <p style="margin: 16px 0 0; padding-top: 16px; border-top: 1px solid #fee2e2; font-size: 14px; color: #b91c1c; line-height: 1.6;">
                                            Our AI-powered system ensures 100% fair and malpractice-free assessments through secure browsers, facial recognition, and live monitoring.
                                        </p>
                                    </td>
                                </tr>
                            </table>

                            <!-- Section Divider -->
                            <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="margin: 30px 0;">
                                <tr>
                                    <td style="border-bottom: 1px solid #e5e7eb;"></td>
                                </tr>
                            </table>

                            <!-- 🚀 Step 3: Taking the Test -->
                            <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="margin-bottom: 24px;">
                                <tr>
                                    <td style="padding: 24px 0 0;">
                                        <h3 style="margin: 0 0 20px; color: #1f2937; font-family: 'Inter', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 20px; font-weight: 600;">
                                            Step 3: Taking the Test
                                        </h3>
                                        
                                        <!-- Item 1 -->
                                        <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="margin-bottom: 16px;">
                                            <tr>
                                                <td style="font-size: 15px; color: #4b5563; line-height: 1.6;">
                                                    <strong>Be on Time:</strong> Launch the application *before* your test window ends. The test will automatically submit when the window closes or the timer expires.
                                                </td>
                                            </tr>
                                        </table>
                                        <!-- Item 2 -->
                                        <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="margin-bottom: 16px;">
                                            <tr>
                                                <td style="font-size: 15px; color: #4b5563; line-height: 1.6;">
                                                    <strong>Use Your Token:</strong> Launch the secure application and paste your unique Access Token to log in.
                                                </td>
                                            </tr>
                                        </table>
                                        <!-- Item 3 -->
                                        <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="margin-bottom: 16px;">
                                            <tr>
                                                <td style="font-size: 15px; color: #4b5563; line-height: 1.6;">
                                                    <strong>One-Time Submission:</strong> You only have one attempt. Once you click "Submit", your test is final. Ensure you have answered all questions.
                                                </td>
                                            </tr>
                                        </table>

                                        <p style="margin: 20px 0 0; padding-top: 20px; border-top: 1px solid #f3f4f6; font-size: 16px; color: #111827; line-height: 1.6; font-weight: 600; text-align: center;">
                                            Show your best. Every click counts toward your success!
                                        </p>
                                    </td>
                                </tr>
                            </table>

                            <!-- Closing -->
                            <p style="margin: 30px 0 16px; font-size: 16px; line-height: 1.6;">Good luck,</p>
                            <p style="margin: 0 0 0; font-size: 16px; line-height: 1.6;"><strong style="color: #111827;">The HireWithUs Assessment Team</strong></p>
                        </td>
                    </tr>
                    
                    <!-- ✅ Footer -->
                    <tr>
                        <td class="footer" align="center" bgcolor="#f9fafb" style="background-color: #f9fafb; padding: 30px 20px; text-align: center; font-size: 13px; color: #6b7280; border-top: 1px solid #e5e7eb; font-family: 'Inter', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6;">
                            
                            <!-- Social Icons Removed -->
                            <p style="margin: 0 0 12px; font-size: 13px; color: #6b7280;">
                                Test sessions are encrypted and GDPR-compliant for complete privacy.
                            </p>
                            
                            <p style="margin: 0 0 8px;">
                                Testing Partner: 
                                <a href="https://testify-lac.com" target="_blank" class="footer-link" style="color: #2563eb; text-decoration: none; font-weight: 600; vertical-align: middle;">
                                    Testify
                                    <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1756037774/Gemini_Generated_Image_eu0ib0eu0ib0eu0i_z0amjh.png" alt="Testify Logo" width="18" style="width: 18px; height: auto; border: 0; vertical-align: middle; margin-left: 4px; margin-top: -2px;">
                                </a>
                            </p>
                            
                            <p style="margin: 0 0 8px;">
                                Need help? 
                                <a href="mailto:support@testify-lac.com" class="footer-link" style="color: #2563eb; text-decoration: none;">support@testify-lac.com</a>
                                <span style="color: #cbd5e1; margin: 0 4px;">|</span>
                                <a href="https://testify-lac.com" target="_blank" class="footer-link" style="color: #2563eb; text-decoration: none;">testify-lac.com</a>
                            </p>
                            
                            <p style="margin: 12px 0 0;">&copy; ${new Date().getFullYear()} | Testify-HireWithUS. All rights reserved.</p>
                        
                        </td>
                    </tr>
                </table>
                
                <!--[if mso | IE]>
                </td>
                </tr>
                </table>
                <![endif]-->

            </td>
        </tr>
    </table>
</body>
</html>


` // (Your email HTML is very long, reusing it here)
             };
            await sendEmailWithSES(mailOptions);
            assignmentsCreated++;
        }
        
        console.log(`[ASSIGN TEST] Successfully assigned test ${testPk} (${testType}) for job ${jobId} to ${assignmentsCreated} candidates.`);
        res.status(200).json({ message: `Test assigned successfully to ${assignmentsCreated} candidates!` });
    } catch (error) {
        console.error("[ASSIGN TEST] Error:", error);
        res.status(500).json({ message: 'Server error assigning test.' });
    }
});

app.get('/api/hiring/coding-test-results', hiringModeratorAuth, async (req, res) => {
    console.log(`[GET /api/hiring/coding-test-results] Request received from moderator: ${req.user.email}`);
    try {
        // 1. Fetch all Coding Tests created by the moderator
        const { Items: codingTests } = await docClient.send(new QueryCommand({
            TableName: HIRING_CODING_TESTS_TABLE,
            IndexName: "createdBy-index",
            KeyConditionExpression: "createdBy = :creator",
            ExpressionAttributeValues: { ":creator": req.user.email }
        }));

        if (!codingTests || codingTests.length === 0) {
            console.log(`[GET /api/hiring/coding-test-results] No coding tests found.`);
            return res.json([]);
        }

        const testIds = codingTests.map(t => t.codingTestId);
        const testMap = new Map(codingTests.map(t => [t.codingTestId, t]));
        console.log(`[GET /api/hiring/coding-test-results] Found ${testIds.length} coding tests.`);

        // 2. Build dynamic filter expressions
        const testIdFilter = testIds.map((_, i) => `:tid${i}`).join(', ');
        const expressionAttributeValues = { ":type": "coding" };
        testIds.forEach((id, i) => expressionAttributeValues[`:tid${i}`] = id);

        // 3. Fetch all assignments for these tests
        const { Items: allAssignments } = await docClient.send(new ScanCommand({
            TableName: HIRING_ASSIGNMENTS_TABLE,
            FilterExpression: `testId IN (${testIdFilter}) AND testType = :type`,
            ExpressionAttributeValues: expressionAttributeValues
        }));
        console.log(`[GET /api/hiring/coding-test-results] Found ${allAssignments.length} total assignments.`);

        // 4. Fetch all results for these tests
        const { Items: allResults } = await docClient.send(new ScanCommand({
            TableName: HIRING_TEST_RESULTS_TABLE,
            FilterExpression: `testId IN (${testIdFilter}) AND testType = :type`,
            ExpressionAttributeValues: expressionAttributeValues
        }));
        console.log(`[GET /api/hiring/coding-test-results] Found ${allResults.length} total results.`);

        // 5. Create a map of results by assignmentId
        const resultMap = new Map(allResults.map(r => [r.assignmentId, r]));
        
        // 6. Process data
        const reports = codingTests.map(test => {
            const testId = test.codingTestId;
            const assignmentsForThisTest = allAssignments.filter(a => a.testId === testId);

            const reportEntries = assignmentsForThisTest.map(assignment => {
                const result = resultMap.get(assignment.assignmentId);
                
                if (result) {
                    // Candidate Attempted
                    return {
                        ...result, // Full result data
                        status: "Attempted",
                        assignmentTime: assignment.assignedAt,
                        windowStart: assignment.startTime,
                        windowEnd: assignment.endTime
                    };
                } else {
                    // Candidate Not Attempted
                    return {
                        resultId: null,
                        assignmentId: assignment.assignmentId,
                        candidateEmail: assignment.studentEmail,
                        status: "Not Attempted",
                        score: null,
                        result: "N/A",
                        submittedAt: null,
                        assignmentTime: assignment.assignedAt,
                        windowStart: assignment.startTime,
                        windowEnd: assignment.endTime,
                        fullName: "N/A (Not Attempted)",
                        collegeName: "N/A",
                        department: "N/A",
                        sectionScores: [] // Provide empty array for consistency
                    };
                }
            });

            // Sort entries
            reportEntries.sort((a, b) => {
                if (a.status < b.status) return 1;
                if (a.status > b.status) return -1;
                return (a.candidateEmail || '').localeCompare(b.candidateEmail || '');
            });

            return {
                testId: testId,
                title: test.title,
                createdAt: test.createdAt,
                report: reportEntries
            };
        });
        
        // Sort tests by creation date
        reports.sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt));

        console.log(`[GET /api/hiring/coding-test-results] Sending ${reports.length} processed test reports.`);
        res.json(reports);
        
    } catch (error) {
        console.error("[GET /api/hiring/coding-test-results] Error:", error);
        res.status(500).json({ message: 'Server error fetching results.' });
    }
});

app.post('/api/hiring/generate-problem-from-pdf', authMiddleware, async (req, res) => {
    // Security check for Hiring Moderator role
    if (req.user.role !== 'Hiring Moderator') {
        return res.status(403).json({ message: 'Access denied.' });
    }

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
                "title": { "type": "STRING" },
                "description": { "type": "STRING" },
                "difficulty": { "type": "STRING", "enum": ["Easy", "Medium", "Hard"] },
                 "score": { "type": "NUMBER" },
                "inputFormat": { "type": "STRING" },
                "outputFormat": { "type": "STRING" },
                "constraints": { "type": "STRING" },
                "example": { "type": "STRING" },
                "testCases": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "input": { "type": "STRING" },
                            "expected": { "type": "STRING" }
                        },
                        "required": ["input", "expected"]
                    }
                }
            },
            required: ["title", "description", "difficulty", "score", "testCases"]
        };

        const apiKey = process.env.GEMINI_API_KEY || 'AIzaSyAR_X4MZ75vxwV7OTU3dabFRcVe4SxWpb8';
        if (!apiKey) {
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
            console.error("Hiring Gemini API Error:", errorBody);
            throw new Error(`AI API call failed with status: ${apiResponse.status}`);
        }

        const result = await apiResponse.json();
        const jsonText = result.candidates[0].content.parts[0].text;
        const structuredProblem = JSON.parse(jsonText);

        res.json(structuredProblem);

    } catch (error) {
        console.error('Error in AI problem generation for hiring:', error);
        res.status(500).json({ message: 'Failed to generate problem using AI.' });
    }
});

app.get('/api/hiring/test-results/:resultId', hiringModeratorAuth, async (req, res) => {
    const { resultId } = req.params;
    console.log(`[GET /api/hiring/test-results] Request for resultId: ${resultId}`);

    try {
        // 1. Fetch the specific result
        const { Item: result } = await docClient.send(new GetCommand({
            TableName: HIRING_TEST_RESULTS_TABLE, Key: { resultId }
        }));

        if (!result) {
            console.warn(`[GET /api/hiring/test-results] Result ${resultId} not found.`);
            return res.status(404).json({ message: 'Result not found.' });
        }
        console.log(`[GET /api/hiring/test-results] Found result for test type: ${result.testType}`);

        // 2. Verify Ownership based on the original test creator
        let testOwnerEmail = null;
        let originalTest = null; // Store the original test definition

        if (result.testType === 'coding') {
            const { Item: test } = await docClient.send(new GetCommand({ TableName: HIRING_CODING_TESTS_TABLE, Key: { codingTestId: result.testId } }));
            testOwnerEmail = test?.createdBy;
            originalTest = test; // Keep the test definition
        } else if (result.testType === 'aptitude') {
            const { Item: test } = await docClient.send(new GetCommand({ TableName: HIRING_APTITUDE_TESTS_TABLE, Key: { aptitudeTestId: result.testId } }));
            testOwnerEmail = test?.createdBy;
            originalTest = test; // Keep the test definition
        } else {
             console.warn(`[GET /api/hiring/test-results] Unknown testType '${result.testType}' for result ${resultId}.`);
             // Decide how to handle unknown types, maybe deny access?
        }

        if (!testOwnerEmail) {
             console.error(`[GET /api/hiring/test-results] Could not find original test or creator for result ${resultId} (Test ID: ${result.testId}, Type: ${result.testType}).`);
             // Consider if this should be a 404 or 500
             return res.status(404).json({ message: 'Original test definition not found.' });
        }

        if (testOwnerEmail !== req.user.email) {
            console.warn(`[GET /api/hiring/test-results] Permission denied for result ${resultId}. Owner: ${testOwnerEmail}, Requester: ${req.user.email}`);
            return res.status(403).json({ message: 'You do not have permission to view this result.' });
        }
        console.log(`[GET /api/hiring/test-results] Ownership verified for result ${resultId}.`);


        // 3. Prepare response - Enhance coding results with section info if not already present
        let finalResultData = { ...result };

        // If it's a coding test AND the section breakdown isn't already stored in the result, calculate it now
        if (result.testType === 'coding' && !finalResultData.sectionScores && originalTest?.sections) {
             console.log(`[GET /api/hiring/test-results] Calculating section scores for result ${resultId} (not found in stored result).`);
             finalResultData.sectionScores = originalTest.sections.map(section => {
                 let sectionTotalScore = 0;
                 let sectionMaxScore = 0;
                 const problemsInSection = section.problems.map(p => p.problemId); // Get IDs of problems in this section

                 // Iterate through the *submissions* stored in the result
                 (finalResultData.submissions || []).forEach(sub => {
                     // Check if the submitted problem belongs to the current section
                     if (problemsInSection.includes(sub.problemId)) {
                         sectionTotalScore += sub.calculatedScore || 0;
                         sectionMaxScore += sub.score || 0; // 'score' here is the max score for the problem
                     }
                 });
                 return {
                     title: section.title,
                     score: sectionTotalScore,
                     maxScore: sectionMaxScore
                 };
             });
              console.log(`[GET /api/hiring/test-results] Calculated section scores:`, finalResultData.sectionScores);
        } else if (result.testType === 'coding' && finalResultData.sectionScores) {
             console.log(`[GET /api/hiring/test-results] Using pre-calculated section scores stored in result ${resultId}.`);
        } else if (result.testType === 'coding' && !originalTest?.sections) {
             console.log(`[GET /api/hiring/test-results] Original test ${result.testId} does not have sections. Skipping section score calculation.`);
        }

        // For aptitude tests, ensure sections->questions->correctAnswer is included if needed by results page
        // (Assuming frontend needs it to display correctness - if not, this step can be skipped)
        if (result.testType === 'aptitude' && originalTest?.sections) {
            console.log(`[GET /api/hiring/test-results] Attaching original aptitude test sections (with answers) for display.`);
            finalResultData.originalTestSections = originalTest.sections; // Attach original sections with answers
        }


        console.log(`[GET /api/hiring/test-results] Sending final data for result ${resultId}.`);
        res.json(finalResultData);

    } catch (error) {
        console.error(`[GET /api/hiring/test-results] Error fetching result ${resultId}:`, error);
        res.status(500).json({ message: 'Server error fetching result details.' });
    }
});


// HIRING MODERATOR: Get Test History
app.get('/api/hiring/test-history', hiringModeratorAuth, async (req, res) => {
    console.log(`[GET /api/hiring/test-history] Request received from moderator: ${req.user.email}`);
    try {
        // 1. Fetch all Aptitude Tests created by the moderator
        const { Items: aptitudeTests } = await docClient.send(new QueryCommand({
            TableName: HIRING_APTITUDE_TESTS_TABLE,
            IndexName: "createdBy-index",
            KeyConditionExpression: "createdBy = :creator",
            ExpressionAttributeValues: { ":creator": req.user.email }
        }));

        if (!aptitudeTests || aptitudeTests.length === 0) {
            console.log(`[GET /api/hiring/test-history] No aptitude tests found.`);
            return res.json([]);
        }
        
        const testIds = aptitudeTests.map(t => t.aptitudeTestId);
        const testMap = new Map(aptitudeTests.map(t => [t.aptitudeTestId, t]));
        console.log(`[GET /api/hiring/test-history] Found ${testIds.length} aptitude tests.`);

        // 2. Build dynamic filter expressions for assignments and results
        const testIdFilter = testIds.map((_, i) => `:tid${i}`).join(', ');
        const expressionAttributeValues = { ":type": "aptitude" };
        testIds.forEach((id, i) => expressionAttributeValues[`:tid${i}`] = id);

        // 3. Fetch all assignments for these tests
        const { Items: allAssignments } = await docClient.send(new ScanCommand({
            TableName: HIRING_ASSIGNMENTS_TABLE,
            FilterExpression: `testId IN (${testIdFilter}) AND testType = :type`,
            ExpressionAttributeValues: expressionAttributeValues
        }));
        console.log(`[GET /api/hiring/test-history] Found ${allAssignments.length} total assignments for these tests.`);

        // 4. Fetch all results for these tests
        const { Items: allResults } = await docClient.send(new ScanCommand({
            TableName: HIRING_TEST_RESULTS_TABLE,
            FilterExpression: `testId IN (${testIdFilter}) AND testType = :type`,
            ExpressionAttributeValues: expressionAttributeValues
        }));
        console.log(`[GET /api/hiring/test-history] Found ${allResults.length} total results for these tests.`);

        // 5. Create a map of results by assignmentId for easy lookup
        const resultMap = new Map(allResults.map(r => [r.assignmentId, r]));

        // 6. Process data
        const history = aptitudeTests.map(test => {
            const testId = test.aptitudeTestId;
            const assignmentsForThisTest = allAssignments.filter(a => a.testId === testId);
            
            const reportEntries = assignmentsForThisTest.map(assignment => {
                const result = resultMap.get(assignment.assignmentId);
                
                if (result) {
                    // Candidate Attempted
                    return {
                        ...result, // Includes all result data (score, submittedAt, etc.)
                        status: "Attempted",
                        assignmentTime: assignment.assignedAt,
                        windowStart: assignment.startTime,
                        windowEnd: assignment.endTime
                    };
                } else {
                    // Candidate Not Attempted
                    return {
                        resultId: null, // No result
                        assignmentId: assignment.assignmentId,
                        candidateEmail: assignment.studentEmail,
                        status: "Not Attempted",
                        score: null,
                        result: "N/A",
                        submittedAt: null,
                        assignmentTime: assignment.assignedAt,
                        windowStart: assignment.startTime,
                        windowEnd: assignment.endTime,
                        // Add basic fields so the table doesn't break
                        fullName: "N/A (Not Attempted)",
                        collegeName: "N/A",
                        department: "N/A"
                    };
                }
            });

            // Sort entries by status (Not Attempted first) then by email
            reportEntries.sort((a, b) => {
                if (a.status < b.status) return 1; // "Not Attempted" comes after "Attempted"
                if (a.status > b.status) return -1;
                return (a.candidateEmail || '').localeCompare(b.candidateEmail || '');
            });

            return {
                testId: testId,
                title: test.title,
                createdAt: test.createdAt,
                report: reportEntries // This is the full report for all assigned candidates
            };
        });
        
        // Sort tests by creation date
        history.sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt));

        console.log(`[GET /api/hiring/test-history] Sending ${history.length} processed test reports.`);
        res.json(history);

    } catch (error) {
        console.error(`[GET /api/hiring/test-history] Error for moderator ${req.user.email}:`, error);
        res.status(500).json({ message: 'Server error fetching test history.' });
    }
});

// EXTERNAL CANDIDATE: Get test details using token
app.get('/api/public/test-details', authMiddleware, async (req, res) => {
    if (!req.user || !req.user.isExternal) { 
        console.warn('[GET TEST DETAILS] Access Denied: Token missing or not external.');
        return res.status(403).json({ message: 'Access denied.' }); 
    }
    
    // Get all details from the token
    const { 
        testId: testPkFromToken, 
        email: candidateEmail, 
        assignmentId,
        isMockTest // <-- THIS IS THE NEW, IMPORTANT FLAG
    } = req.user;

    console.log(`[GET TEST DETAILS] Request for assignmentId: ${assignmentId}, testPkFromToken: ${testPkFromToken}, email: ${candidateEmail}, isMock: ${isMockTest}`);

    try {
        const { Item: assignment } = await docClient.send(new GetCommand({ TableName: HIRING_ASSIGNMENTS_TABLE, Key: { assignmentId } }));

        // --- MODIFICATION: Check if it's a mock test FIRST ---
        if (!isMockTest) {
            // --- This is the STANDARD hiring flow ---
            console.log(`[GET TEST DETAILS] Standard flow. Validating assignment...`);
            if (!assignment || assignment.studentEmail !== candidateEmail || assignment.testId !== testPkFromToken) { 
                console.warn(`[GET TEST DETAILS] Standard flow FAILED: Link invalid or assignment details mismatch.`);
                return res.status(403).json({ message: 'Link invalid or assignment details mismatch.' }); 
            }
            console.log(`[GET TEST DETAILS] Assignment ${assignmentId} found. Type: ${assignment.testType}, Test PK: ${assignment.testId}`);

            const now = new Date();
            const startTime = new Date(assignment.startTime); 
            const endTime = new Date(assignment.endTime); 

            if (now < startTime || now > endTime) {
                 const reason = now < startTime ? 'not yet active' : 'expired';
                 console.warn(`[GET TEST DETAILS] Assignment ${assignmentId} outside active window (${reason}).`);
                 return res.status(403).json({ message: `This test link is ${reason}.` });
            }
            console.log(`[GET TEST DETAILS] Assignment ${assignmentId} is within the active time window.`);

            const GSI_NAME = 'AssignmentIdIndex';
            console.log(`[GET TEST DETAILS] Checking for existing SUBMITTED results...`);
            const { Items: existingSubmittedResults } = await docClient.send(new QueryCommand({ 
                TableName: HIRING_TEST_RESULTS_TABLE, IndexName: GSI_NAME,
                KeyConditionExpression: 'assignmentId = :aid',
                FilterExpression: 'attribute_not_exists(resultId) OR not begins_with(resultId, :initPrefix)',
                ExpressionAttributeValues: { ':aid': assignmentId, ':initPrefix': 'init_' },
                Limit: 1
           }));
           if (existingSubmittedResults && existingSubmittedResults.length > 0) {
               console.warn(`[GET TEST DETAILS] Test already SUBMITTED for assignment ${assignmentId}.`);
               return res.status(403).json({ message: 'This test link has already been used to submit results.' });
           }
           console.log(`[GET TEST DETAILS] No previous SUBMITTED result found.`);
           // --- End of Standard Logic ---

        } else {
            // --- This is a MOCK test ---
            // We bypass all the checks above (assignment, time, submission).
            console.log(`[GET TEST DETAILS] MOCK TEST flow: Bypassing assignment, time, and submission checks for ${assignmentId}`);
        }
        // --- END OF MODIFICATION ---
        
        // --- Fetch Actual Test Details (This logic works for both flows) ---
        let test;
        let targetTableName;
        let targetPkName;
        
        // --- MODIFICATION: Get testType from assignment OR token ---
        // For standard flow, get from `assignment`.
        // For mock flow, `assignment` is null, so get from `req.user` (the token payload).
        const testType = assignment ? assignment.testType : req.user.testType;
        if (!testType) {
            console.error(`[GET TEST DETAILS] Fatal: testType is missing for ${assignmentId}. Token:`, req.user);
            return res.status(500).json({ message: 'Internal Server Error: Test type undefined.' });
        }
        // --- END OF MODIFICATION ---
        
        console.log(`[GET TEST DETAILS] Fetching test details for testType: ${testType}`);

        if (testType === 'coding') {
            targetTableName = HIRING_CODING_TESTS_TABLE; targetPkName = 'codingTestId';
            const { Item } = await docClient.send(new GetCommand({ TableName: targetTableName, Key: { [targetPkName]: testPkFromToken } }));
            test = Item;
        } else if (testType === 'aptitude') {
            targetTableName = HIRING_APTITUDE_TESTS_TABLE; targetPkName = 'aptitudeTestId';
            const { Item } = await docClient.send(new GetCommand({ TableName: targetTableName, Key: { [targetPkName]: testPkFromToken } }));
            test = Item;
        } else {
             console.error(`[GET TEST DETAILS] Invalid testType '${testType}' in assignment ${assignmentId}.`);
             return res.status(500).json({ message: 'Internal Server Error: Invalid test type.' });
        }
        
        if (!test) {
            console.error(`[GET TEST DETAILS] Test definition ${testPkFromToken} (Type: ${testType}) not found in ${targetTableName}.`);
             return res.status(404).json({ message: 'Test content not found.' });
        }
        console.log(`[GET TEST DETAILS] Successfully fetched test definition: ${test.title}`);

        // --- Prepare Test Data for Frontend ---
        let processedTest = { ...test };
        processedTest.assignmentId = assignmentId; 
        processedTest.testType = testType; // Pass the testType
        
        // --- MODIFICATION: Explicitly pass the isMockTest flag to the Electron app ---
        processedTest.isMockTest = isMockTest || false;

        // (aptitude answer removal logic)
        if (testType === 'aptitude' && processedTest.sections && Array.isArray(processedTest.sections)) {
            processedTest.sections = processedTest.sections.map(section => {
                 const questionsArray = (section.questions && Array.isArray(section.questions)) ? section.questions : [];
                 const questions = questionsArray.map(q => { const { correctAnswer, correctAnswers, ...qData } = q; return qData; });
                 return { ...section, questions }; 
            });
            console.log(`[GET TEST DETAILS] Removed answers from aptitude test sections.`);
        }
        // (coding problem info extraction logic)
        else if (testType === 'coding') {
            if (processedTest.sections && Array.isArray(processedTest.sections)) {
                processedTest.sections = processedTest.sections.map(section => {
                    const problemsArray = (section.problems && Array.isArray(section.problems)) ? section.problems : [];
                    return {
                        title: section.title,
                        sectionTimer: section.sectionTimer,
                        sectionQualifyingMarks: section.sectionQualifyingMarks,
                        problems: problemsArray.map(p => ({
                            problemId: p.problemId, title: p.title, difficulty: p.difficulty, score: p.score
                        }))
                    };
                });
            }
            console.log(`[GET TEST DETAILS] Processed coding test sections.`);
        }

        console.log(`[GET TEST DETAILS] Returning processed test data. isMockTest: ${processedTest.isMockTest}`);
        res.json(processedTest);

    } catch (error) {
        console.error(`[GET TEST DETAILS] Fatal Error processing assignment ${assignmentId}:`, error);
        res.status(500).json({ message: 'Server error fetching test details. Please contact support.' });
    }
});
// EXTERNAL CANDIDATE: Submit Test
app.post('/api/public/submit-test', authMiddleware, async (req, res) => {
    if (!req.user || !req.user.isExternal) {
        return res.status(403).json({ message: 'Access denied. Valid candidate token required.' });
    }
    
    const { testId: testPkFromToken, email: candidateEmail, assignmentId } = req.user;
    const { answers, timeTaken, violationReason, fullName, rollNumber, collegeName, department, profileImageUrl } = req.body;

    if (!fullName || !rollNumber || !collegeName || !department) {
         return res.status(400).json({ message: 'Missing required candidate details.' });
    }
    if (!Array.isArray(answers)) {
        return res.status(400).json({ message: "Invalid answers format." });
    }

    const resultId = `har_${uuidv4()}`;

    try {
        // --- 1. Verify Assignment Record ---
        const { Item: assignment } = await docClient.send(new GetCommand({
            TableName: HIRING_ASSIGNMENTS_TABLE,
            Key: { assignmentId }
        }));

        if (!assignment || assignment.studentEmail !== candidateEmail || assignment.testId !== testPkFromToken) {
             return res.status(403).json({ message: 'Assignment validation failed.' });
        }
        if (assignment.testType !== 'aptitude') {
            return res.status(403).json({ message: 'Assignment is not for an aptitude test.' });
        }
        
        const jobId = assignment.jobId || null;

        // --- 2. Check for Previous *SUBMITTED* Result ---
        const { Items: existingSubmittedResults } = await docClient.send(new QueryCommand({
             TableName: HIRING_TEST_RESULTS_TABLE,
             IndexName: 'AssignmentIdIndex',
             KeyConditionExpression: 'assignmentId = :aid',
             FilterExpression: 'attribute_not_exists(resultId) OR not begins_with(resultId, :initPrefix)',
             ExpressionAttributeValues: { ':aid': assignmentId, ':initPrefix': 'init_' },
             Limit: 1
        }));
        if (existingSubmittedResults && existingSubmittedResults.length > 0) {
            return res.status(409).json({ message: 'This test has already been submitted.' });
        }

        // --- 3. Fetch Aptitude Test Definition ---
        const { Item: test } = await docClient.send(new GetCommand({
            TableName: HIRING_APTITUDE_TESTS_TABLE,
            Key: { aptitudeTestId: assignment.testId } 
        }));

        if (!test) {
            return res.status(404).json({ message: "Test definition not found." });
        }

        // --- 4. Score Calculation ---
        let marksScored = 0;
        const allQuestions = test.sections?.flatMap(s => s.questions || []) || [];
        
        allQuestions.forEach((question, index) => {
            const studentAnswer = answers?.[index];
            const answerProvided = studentAnswer !== null && studentAnswer !== undefined;
            const isCorrect = answerProvided &&
                              String(studentAnswer).trim().toLowerCase() === String(question.correctAnswer).trim().toLowerCase();
            if (isCorrect) {
                marksScored += (parseInt(question.marks, 10) || 0);
            }
        });

        const totalMarks = parseInt(test.totalMarks, 10) || 0;
        const passingPercentage = parseInt(test.passingPercentage, 10) || 0;
        const percentageScore = totalMarks > 0 ? Math.round((marksScored / totalMarks) * 100) : 0;
        const resultStatus = percentageScore >= passingPercentage ? "Pass" : "Fail";

        // --- 5. Construct Result Object ---
        const newResult = {
            resultId,
            testId: assignment.testId,
            assignmentId,
            jobId: jobId, 
            testType: 'aptitude',
            candidateEmail,
            fullName,
            rollNumber,
            collegeName,
            department,
            profileImageUrl: profileImageUrl || null,
            testTitle: test.title || 'N/A',
            answers,
            timeTaken: timeTaken || 0,
            score: percentageScore,
            marksScored,
            totalMarks,
            result: resultStatus,
            submittedAt: new Date().toISOString(),
            violationReason: violationReason || null,
        };

        // --- 6. Save Result ---
        await docClient.send(new PutCommand({
            TableName: HIRING_TEST_RESULTS_TABLE,
            Item: newResult
        }));
        
        res.status(201).json({ message: 'Test submitted successfully!' });

    } catch (error) {
        console.error(`[SUBMIT APTITUDE] FATAL ERROR processing assignment ${assignmentId}:`, error);
        res.status(500).json({ message: 'Server error submitting test. Please contact support.' });
    }
});


// HIRING MODERATOR: Add a new college to their list
app.post('/api/hiring/colleges', hiringModeratorAuth, async (req, res) => {
    const { collegeName } = req.body;
    if (!collegeName) return res.status(400).json({ message: 'College name is required.' });
    const collegeId = `hcollege_${uuidv4()}`;
    const newCollege = {
        collegeId, collegeName, createdBy: req.user.email
    };
    try {
        await docClient.send(new PutCommand({ TableName: HIRING_COLLEGES_TABLE, Item: newCollege }));
        res.status(201).json({ message: 'College added successfully.' });
    } catch (error) {
        console.error("Add College Error:", error);
        res.status(500).json({ message: 'Server error adding college.' });
    }
});

// HIRING MODERATOR: Get their list of colleges
app.get('/api/hiring/colleges', hiringModeratorAuth, async (req, res) => {
    try {
        const { Items } = await docClient.send(new QueryCommand({
            TableName: HIRING_COLLEGES_TABLE,
            IndexName: "createdBy-index",
            KeyConditionExpression: "createdBy = :creator",
            ExpressionAttributeValues: { ":creator": req.user.email }
        }));
        // Sort alphabetically by name before sending
        (Items || []).sort((a, b) => (a.collegeName || '').localeCompare(b.collegeName || ''));
        res.json(Items || []);
    } catch (error) {
        console.error("Get Moderator Colleges Error:", error);
        res.status(500).json({ message: 'Server error fetching colleges.' });
    }
});

// HIRING MODERATOR: Delete a college from their list
app.delete('/api/hiring/colleges/:collegeId', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Hiring Moderator') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { collegeId } = req.params;
    try {
        // Security check: ensure the moderator owns this college entr
        // y
        const { Item } = await docClient.send(new GetCommand({ TableName: "HIRING_COLLEGES_TABLE", Key: { collegeId } }));
        if (!Item || Item.createdBy !== req.user.email) {
            return res.status(403).json({ message: 'You do not have permission to delete this college.' });
        }
        await docClient.send(new DeleteCommand({ TableName: "TestifyColleges", Key: { collegeId } }));
        res.json({ message: 'College deleted successfully.' });
    } catch (error) {
        console.error("Delete Hiring College Error:", error);
        res.status(500).json({ message: 'Server error deleting college.' });
    }
});


// PUBLIC: Get colleges for a specific test (for the student dropdown)
app.get('/api/public/colleges/:testId', async (req, res) => {
    const { testId } = req.params;
    console.log(`[GET /api/public/colleges] Request received for testId: ${testId}`);

    try {
        let testCreatorEmail = null;
        let testFound = false;

        // 1. Determine the test type and find the creator's email
        // --- CHANGE: Check APTITUDE table first ---
        console.log(`[GET /api/public/colleges] Checking ${HIRING_APTITUDE_TESTS_TABLE} for ID: ${testId}`);
        const { Item: aptitudeTest } = await docClient.send(new GetCommand({
            TableName: HIRING_APTITUDE_TESTS_TABLE,
            Key: { aptitudeTestId: testId } // Primary key for aptitude tests
        }));

        if (aptitudeTest && aptitudeTest.createdBy) {
            testCreatorEmail = aptitudeTest.createdBy;
            testFound = true;
            console.log(`[GET /api/public/colleges] Found APTITUDE test created by: ${testCreatorEmail}`);
        } else {
            // If not found as aptitude test, check if it's a coding test
            console.log(`[GET /api/public/colleges] Aptitude test not found. Checking ${HIRING_CODING_TESTS_TABLE} for ID: ${testId}`);
            const { Item: codingTest } = await docClient.send(new GetCommand({
                TableName: HIRING_CODING_TESTS_TABLE,
                Key: { codingTestId: testId } // Primary key for coding tests
            }));

            if (codingTest && codingTest.createdBy) {
                testCreatorEmail = codingTest.createdBy;
                testFound = true;
                console.log(`[GET /api/public/colleges] Found CODING test created by: ${testCreatorEmail}`);
            }
        }

        // 2. If no creator found after checking relevant tables, return error
        if (!testFound || !testCreatorEmail) {
            // --- Log which tables were checked ---
            console.warn(`[GET /api/public/colleges] Test creator not found for testId: ${testId} after checking ${HIRING_APTITUDE_TESTS_TABLE} and ${HIRING_CODING_TESTS_TABLE}.`);
            // Return 404 specifically for this case
            return res.status(404).json({ message: 'Test creator not found.' });
        }

        // 3. Fetch colleges associated with that creator from the HIRING_COLLEGES_TABLE
        console.log(`[GET /api/public/colleges] Fetching colleges from ${HIRING_COLLEGES_TABLE} for creator: ${testCreatorEmail}`);
        const { Items } = await docClient.send(new QueryCommand({
            TableName: HIRING_COLLEGES_TABLE,
            IndexName: "createdBy-index", // Assumes a GSI on HIRING_COLLEGES_TABLE with 'createdBy' as the partition key
            KeyConditionExpression: "createdBy = :creator",
            ExpressionAttributeValues: { ":creator": testCreatorEmail }
        }));

        console.log(`[GET /api/public/colleges] Found ${Items ? Items.length : 0} colleges for creator ${testCreatorEmail}.`);

        // Sort alphabetically by name before sending
        const colleges = Items || [];
        colleges.sort((a, b) => (a.collegeName || '').localeCompare(b.collegeName || ''));

        res.json(colleges); // Send the list

    } catch (error) {
        console.error(`[GET /api/public/colleges] Error fetching public colleges for test ${testId}:`, error);
        // Handle potential DynamoDB errors
        if (error.name === 'ResourceNotFoundException' || (error.message && error.message.includes('index'))) {
             console.error("[GET /api/public/colleges] Critical Error: DynamoDB index 'createdBy-index' might be missing on HIRING_COLLEGES_TABLE.");
             return res.status(500).json({ message: 'Server configuration error fetching colleges.' });
        }
        res.status(500).json({ message: 'Server error fetching public colleges.' });
    }
});

app.post('/api/quizcom/quizzes/start', authMiddleware, quizModeratorAuth, async (req, res) => {
    const { quizId } = req.body;
    try {
        const { Item: originalQuiz } = await docClient.send(new GetCommand({ TableName: "TestifyTests", Key: { testId: quizId }}));
        if (!originalQuiz) return res.status(404).json({ message: "Original quiz not found." });

        const liveQuizId = `live_${uuidv4()}`;
        const quizCode = Math.floor(100000 + Math.random() * 900000).toString();

        const newLiveQuiz = {
            liveQuizId,
            originalQuizId: quizId,
            title: originalQuiz.title,
            logoUrl: originalQuiz.logoUrl, // <-- ADD THIS LINE
            quizCode,
            status: 'waiting',
            currentQuestionIndex: -1,
            participants: [],
            moderator: req.user.email,
            createdAt: new Date().toISOString()
        };
        await docClient.send(new PutCommand({ TableName: "TestifyLiveQuizzes", Item: newLiveQuiz }));
        res.status(201).json({ message: 'Quiz started!', liveQuizId, quizCode });
    } catch (error) {
        console.error("Start Quiz Error:", error);
        res.status(500).json({ message: 'Server error starting quiz.' });
    }
});

// Get Live Quiz Details (for moderator view)
app.get('/api/quizcom/live/:id', authMiddleware, quizModeratorAuth, async (req, res) => {
    try {
        const { Item } = await docClient.send(new GetCommand({ TableName: "TestifyLiveQuizzes", Key: { liveQuizId: req.params.id }}));
        if (!Item || Item.moderator !== req.user.email) return res.status(404).json({ message: 'Live quiz session not found or access denied.' });
        res.json(Item);
    } catch (error) {
        console.error("Get Live Quiz Details Error:", error);
        res.status(500).json({ message: 'Server error fetching live quiz details.' });
    }
});


// Join a quiz lobby
app.post('/api/quizcom/join', async (req, res) => {
    const { quizCode } = req.body;
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyLiveQuizzes",
            FilterExpression: "quizCode = :code AND #status IN (:s1, :s2)",
            ExpressionAttributeNames: { "#status": "status" },
            ExpressionAttributeValues: { ":code": quizCode, ":s1": "waiting", ":s2": "scheduled" }
        }));
        if (!Items || Items.length === 0) return res.status(404).json({ message: "Invalid or inactive quiz code." });
        res.json({ message: "Quiz found! Please enter your details.", liveQuizId: Items[0].liveQuizId });
    } catch (error) {
        console.error("Join Quiz Error:", error);
        res.status(500).json({ message: 'Server error joining quiz.' });
    }
});

app.get('/api/quizcom/history', authMiddleware, quizModeratorAuth, async (req, res) => {
    try {
        const { Items: liveQuizzes } = await docClient.send(new ScanCommand({
            TableName: "TestifyLiveQuizzes",
            FilterExpression: "moderator = :moderator AND #s = :status",
            ExpressionAttributeNames: { "#s": "status" },
            ExpressionAttributeValues: { 
                ":moderator": req.user.email,
                ":status": "completed"
            }
        }));

        const history = liveQuizzes.map(quiz => {
            const totalScore = quiz.participants.reduce((acc, p) => acc + p.score, 0);
            const averageScore = quiz.participants.length > 0 ? Math.round(totalScore / quiz.participants.length) : 0;
            return {
                liveQuizId: quiz.liveQuizId,
                title: quiz.title,
                conductedOn: quiz.createdAt,
                participantCount: quiz.participants.length,
                averageScore
            };
        });
        
        history.sort((a,b) => new Date(b.conductedOn) - new Date(a.conductedOn));

        res.json(history);
    } catch (error) {
        console.error("Get Quiz History Error:", error);
        res.status(500).json({ message: 'Server error fetching quiz history.' });
    }
});

app.get('/api/quizcom/dashboard-stats', authMiddleware, quizModeratorAuth, async (req, res) => {
    try {
        // Fetch quizzes created by the moderator
        const { Items: createdQuizzes } = await docClient.send(new ScanCommand({
            TableName: "TestifyTests",
            FilterExpression: "testType = :type AND createdBy = :creator",
            ExpressionAttributeValues: { ":type": "quizcom", ":creator": req.user.email }
        }));

        // Fetch live quiz sessions started by the moderator
        const { Items: liveQuizzes } = await docClient.send(new ScanCommand({
            TableName: "TestifyLiveQuizzes",
            FilterExpression: "moderator = :moderator",
            ExpressionAttributeValues: { ":moderator": req.user.email }
        }));

        const totalParticipants = liveQuizzes.reduce((acc, quiz) => acc + (quiz.participants ? quiz.participants.length : 0), 0);
        const activeLiveQuizzes = liveQuizzes.filter(q => q.status === 'waiting' || q.status === 'active').length;
        const completedQuizzes = liveQuizzes.filter(q => q.status === 'completed').length;

       res.json({
            totalQuizzes: createdQuizzes.length,
            liveQuizzes: activeLiveQuizzes,
            totalParticipants,
            completedQuizzes
        });
    } catch (error) {
        console.error("Get Dashboard Stats Error:", error);
        res.status(500).json({ message: 'Server error fetching dashboard stats.' });
    }
});

app.post('/api/quizcom/quizzes', authMiddleware, quizModeratorAuth, async (req, res) => {
    const { title, questions, logoUrl } = req.body; // <-- ADD logoUrl here
    const testId = `quizcom_${uuidv4()}`;

    const newQuiz = {
        testId,
        title,
        logoUrl, // <-- ADD THIS LINE
        questions,
        testType: 'quizcom',
        createdBy: req.user.email,
        createdAt: new Date().toISOString()
    };

    try {
        await docClient.send(new PutCommand({ TableName: "TestifyTests", Item: newQuiz }));
        res.status(201).json({ message: 'Quiz created successfully!', quiz: newQuiz });
    } catch (error) {
        console.error("Create QuizCom Error:", error);
        res.status(500).json({ message: 'Server error creating quiz.' });
    }
});

app.get('/api/quizcom/quizzes', authMiddleware, quizModeratorAuth, async (req, res) => {
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyTests",
            FilterExpression: "testType = :type AND createdBy = :creator",
            ExpressionAttributeValues: { ":type": "quizcom", ":creator": req.user.email }
        }));
        res.json(Items || []);
    } catch (error) {
        console.error("Get Quizzes Error:", error);
        res.status(500).json({ message: 'Server error fetching quizzes.' });
    }
});
app.get('/api/quizcom/quizzes/:id', authMiddleware, quizModeratorAuth, async (req, res) => {
    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: "TestifyTests",
            Key: { testId: req.params.id }
        }));
        
        // Security check: Ensure the quiz belongs to the logged-in moderator
        if (Item && Item.createdBy === req.user.email) {
            res.json(Item);
        } else {
            res.status(404).json({ message: 'Quiz not found or you do not have permission to access it.' });
        }
    } catch (error) {
        console.error("Get Single Quiz Error:", error);
        res.status(500).json({ message: 'Server error fetching quiz.' });
    }
});

// PUT: Update a quiz
app.put('/api/quizcom/quizzes/:id', authMiddleware, quizModeratorAuth, async (req, res) => {
    const { title, questions } = req.body;
    const { id } = req.params;

    try {
        // First, verify the moderator owns this quiz
        const { Item: existingQuiz } = await docClient.send(new GetCommand({
            TableName: "TestifyTests",
            Key: { testId: id }
        }));
        if (!existingQuiz || existingQuiz.createdBy !== req.user.email) {
            return res.status(403).json({ message: 'You do not have permission to modify this quiz.' });
        }

        const updatedQuiz = {
            ...existingQuiz,
            title,
            questions
        };

        await docClient.send(new PutCommand({ TableName: "TestifyTests", Item: updatedQuiz }));
        res.status(200).json({ message: 'Quiz updated successfully!', quiz: updatedQuiz });
    } catch (error) {
        console.error("Update Quiz Error:", error);
        res.status(500).json({ message: 'Server error updating quiz.' });
    }
});

app.delete('/api/quizcom/quizzes/:id', authMiddleware, quizModeratorAuth, async (req, res) => {
    const { id } = req.params;
    try {
        const { Item: existingQuiz } = await docClient.send(new GetCommand({
            TableName: "TestifyTests",
            Key: { testId: id }
        }));
        if (!existingQuiz || existingQuiz.createdBy !== req.user.email) {
            return res.status(403).json({ message: 'You do not have permission to delete this quiz.' });
        }

        await docClient.send(new DeleteCommand({ TableName: "TestifyTests", Key: { testId: id } }));
        res.status(200).json({ message: 'Quiz deleted successfully.' });
    } catch (error) {
        console.error("Delete Quiz Error:", error);
        res.status(500).json({ message: 'Server error deleting quiz.' });
    }
});

app.post('/api/upload-image', authMiddleware, upload.single('image'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No image file uploaded.' });
    }
    try {
        const b64 = Buffer.from(req.file.buffer).toString("base64");
        let dataURI = "data:" + req.file.mimetype + ";base64," + b64;
        const result = await cloudinary.uploader.upload(dataURI, {
            folder: "quiz_images"
        });
        res.json({ message: 'Image uploaded successfully.', imageUrl: result.secure_url });
    } catch (error) {
        console.error("Image Upload Error:", error);
        res.status(500).json({ message: 'Server error uploading image.' });
    }
});

app.post('/api/quizcom/quizzes/assign', authMiddleware, quizModeratorAuth, async (req, res) => {
    const { quizId, emails, checkInTime, startTime } = req.body;
    
    // This is a placeholder for the logic. You would typically:
    // 1. Save the assignment details to a new 'TestifyQuizAssignments' table.
    // 2. Create unique links/tokens for each student.
    // 3. Email the links to the students.
    
    console.log('Assigning quiz:', { quizId, emails, checkInTime, startTime });
    
    // For now, we'll just return a success message.
    res.status(200).json({ message: 'Quiz assigned successfully (logic to be implemented).' });
});

// =================================================================
// --- END HIRE WITH US ---
// =================================================================

app.get('/api/quizcom/report/:id', authMiddleware, quizModeratorAuth, async (req, res) => {
    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: "TestifyLiveQuizzes",
            Key: { liveQuizId: req.params.id }
        }));
        
        // Security check: ensure the report being accessed belongs to the logged-in moderator
        if (Item && Item.moderator === req.user.email) {
            res.json(Item);
        } else {
            res.status(404).json({ message: 'Quiz report not found or you do not have permission to access it.' });
        }
    } catch (error) {
        console.error("Get Quiz Report Error:", error);
        res.status(500).json({ message: 'Server error fetching quiz report.' });
    }
});

app.post('/api/quizcom/join-by-code', async (req, res) => {
    const { quizCode } = req.body;
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyLiveQuizzes",
            FilterExpression: "quizCode = :code AND #status IN (:s1, :s2)",
            ExpressionAttributeNames: { "#status": "status" },
            ExpressionAttributeValues: { ":code": quizCode, ":s1": "waiting", ":s2": "scheduled" }
        }));
        if (!Items || Items.length === 0) {
            return res.status(404).json({ message: "Invalid or inactive quiz code." });
        }
        res.json({ liveQuizId: Items[0].liveQuizId });
    } catch (error) {
        console.error("Join By Code Error:", error);
        res.status(500).json({ message: 'Server error joining quiz.' });
    }
});

app.get('/api/quizcom/live/:id/details', async (req, res) => {
    try {
        const { Item } = await docClient.send(new GetCommand({ 
            TableName: "TestifyLiveQuizzes", 
            Key: { liveQuizId: req.params.id }
        }));
        
        if (Item) {
            // Send only public-safe data
            res.json({ 
                title: Item.title,
                logoUrl: Item.logoUrl 
            });
        } else {
            res.status(404).json({ message: 'Live quiz not found.' });
        }
    } catch (error) {
        console.error("Get Live Quiz Public Details Error:", error);
        res.status(500).json({ message: 'Server error fetching quiz details.' });
    }
});

// =================================================================
// --- NEW JOB & APPLICATION ROUTES FOR HIRING MODERATOR ---
// =================================================================

// Note: Using TestifyUsers table to store jobs and applications to avoid creating new tables as requested.
// We will use a `recordType` attribute to distinguish between users, jobs, and applications.

const HIRING_TABLE = "TestifyUsers"; // Using a single table for this feature

// HIRING MODERATOR: Create a new Job Posting
app.post('/api/hiring/jobs', hiringModeratorAuth, async (req, res) => {
    const { title, description, eligibleColleges, applicationDeadline, hiringTimeline } = req.body;
    if (!title || !description || !eligibleColleges || !applicationDeadline || !hiringTimeline) {
        return res.status(400).json({ message: 'All fields are required.' });
    }
    const jobId = `job_${uuidv4()}`;
    const newJob = {
        jobId, title, description, eligibleColleges, applicationDeadline, hiringTimeline,
        createdBy: req.user.email, createdAt: new Date().toISOString()
    };
    try {
        await docClient.send(new PutCommand({ TableName: HIRING_JOBS_TABLE, Item: newJob }));
        res.status(201).json({ message: 'Job created successfully!', job: newJob });
    } catch (error) {
        console.error("Create Job Error:", error);
        res.status(500).json({ message: 'Server error creating job.' });
    }
});// HIRING MODERATOR: Get all jobs they have created
app.get('/api/hiring/jobs', hiringModeratorAuth, async (req, res) => {
    try {
        const { Items } = await docClient.send(new QueryCommand({
            TableName: HIRING_JOBS_TABLE,
            IndexName: "createdBy-index",
            KeyConditionExpression: "createdBy = :creator",
            ExpressionAttributeValues: { ":creator": req.user.email }
        }));
         // Map jobId to testId for frontend compatibility if needed, otherwise send as is
         res.json((Items || []).map(job => ({ ...job, testId: job.jobId })));
    } catch (error) {
        console.error("Get Moderator Jobs Error:", error);
        res.status(500).json({ message: 'Server error fetching jobs.' });
    }
});

// PUBLIC: Get all open job listings
app.get('/api/public/jobs', async (req, res) => {
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: HIRING_TABLE,
            FilterExpression: "recordType = :type AND applicationDeadline > :now",
            ExpressionAttributeValues: { ":type": "JOB", ":now": new Date().toISOString() }
        }));
        res.json(Items);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching jobs.' });
    }
});

// PUBLIC: Get details for a single job
// app.get('/api/public/jobs/:jobId', async (req, res) => {
//     try {
//         const { Item } = await docClient.send(new GetCommand({
//             TableName: HIRING_TABLE,
//             Key: { email: req.params.jobId }
//         }));
//         if (Item && Item.recordType === 'JOB') {
//             res.json(Item);
//         } else {
//             res.status(404).json({ message: 'Job not found.' });
//         }
//     } catch (error) {
//         res.status(500).json({ message: 'Server error fetching job details.' });
//     }
// });

// PUBLIC: Apply for a job
app.post('/api/public/apply/:jobId', upload.any(), async (req, res) => {
    // ... (data extraction) ...
    try {
        const { Item: job } = await docClient.send(new GetCommand({ TableName: HIRING_JOBS_TABLE, Key: { jobId: req.params.jobId } }));
        if (!job || new Date(job.applicationDeadline) < new Date()) {
            return res.status(400).json({ message: 'Job not found or deadline passed.' });
        }
        // ... (file upload logic using uploadToCloudinary) ...
        const applicationId = `app_${uuidv4()}`;
        const newApplication = { applicationId, jobId: req.params.jobId, jobTitle: job.title, /* ... other fields ... */ appliedAt: new Date().toISOString() };
        await docClient.send(new PutCommand({ TableName: HIRING_APPLICATIONS_TABLE, Item: newApplication }));
        res.status(201).json({ message: 'Application submitted successfully!' });
    } catch (error) {
        console.error("Apply Job Error:", error);
        res.status(500).json({ message: 'Server error submitting application.' });
    }
})

// HIRING MODERATOR: Get applications for a specific job
app.get('/api/hiring/jobs/:jobId/applications', hiringModeratorAuth, async (req, res) => {
    const { jobId } = req.params;
    console.log(`[GET /api/hiring/jobs/${jobId}/applications] Request received from moderator: ${req.user.email}`);
    
    try {
        // --- 1. Verify Job Ownership ---
        console.log(`[GET /api/hiring/jobs/${jobId}/applications] Fetching job details from ${HIRING_JOBS_TABLE}`);
        const { Item: job } = await docClient.send(new GetCommand({
            TableName: HIRING_JOBS_TABLE,
            Key: { jobId }
        }));
        if (!job || job.createdBy !== req.user.email) {
             console.warn(`[GET /api/hiring/jobs/${jobId}/applications] Permission denied or job not found.`);
            return res.status(403).json({ message: "Permission denied or job not found." });
        }
        console.log(`[GET /api/hiring/jobs/${jobId}/applications] Job found: ${job.title}`);

        // --- 2. Fetch All Applications for this Job ---
        console.log(`[GET /api/hiring/jobs/${jobId}/applications] Fetching applications from ${HIRING_APPLICATIONS_TABLE}`);
        const { Items: applications } = await docClient.send(new QueryCommand({
            TableName: HIRING_APPLICATIONS_TABLE,
            IndexName: "jobId-index", // Assumes GSI with HASH = jobId
            KeyConditionExpression: "jobId = :jid",
            ExpressionAttributeValues: { ":jid": jobId }
        }));
        if (!applications || applications.length === 0) {
            console.log(`[GET /api/hiring/jobs/${jobId}/applications] No applications found for this job.`);
            return res.json({ jobTitle: job.title, applications: [], testHeaders: [] });
        }
        console.log(`[GET /api/hiring/jobs/${jobId}/applications] Found ${applications.length} applications.`);
        const applicantEmailMap = new Map(applications.map(app => [app.email, app]));

        // --- 3. Fetch All Assignments for this Job ---
        console.log(`[GET /api/hiring/jobs/${jobId}/applications] Fetching assignments from ${HIRING_ASSIGNMENTS_TABLE}`);
        const { Items: assignments } = await docClient.send(new ScanCommand({
            TableName: HIRING_ASSIGNMENTS_TABLE,
            FilterExpression: "jobId = :jid",
            ExpressionAttributeValues: { ":jid": jobId }
        }));
        console.log(`[GET /api/hiring/jobs/${jobId}/applications] Found ${assignments.length} assignments.`);

        // --- 4. Fetch All Test Results for this Job ---
        console.log(`[GET /api/hiring/jobs/${jobId}/applications] Fetching results from ${HIRING_TEST_RESULTS_TABLE}`);
        const { Items: results } = await docClient.send(new ScanCommand({
            TableName: HIRING_TEST_RESULTS_TABLE,
            FilterExpression: "jobId = :jid",
            ExpressionAttributeValues: { ":jid": jobId }
        }));
        console.log(`[GET /api/hiring/jobs/${jobId}/applications] Found ${results.length} results.`);
        const resultMap = new Map(results.map(res => [res.assignmentId, res]));

        // --- 5. Get Test Definitions (Names/Titles) ---
        const testIds = [...new Set(assignments.map(a => a.testId))];
        const aptitudeTestKeys = testIds.map(id => ({ aptitudeTestId: id }));
        const codingTestKeys = testIds.map(id => ({ codingTestId: id }));
        let testMap = new Map();

        if (aptitudeTestKeys.length > 0) {
            const { Responses } = await docClient.send(new BatchGetCommand({
                RequestItems: { [HIRING_APTITUDE_TESTS_TABLE]: { Keys: aptitudeTestKeys, ProjectionExpression: "aptitudeTestId, title" } }
            }));
            (Responses[HIRING_APTITUDE_TESTS_TABLE] || []).forEach(t => testMap.set(t.aptitudeTestId, t.title));
        }
        if (codingTestKeys.length > 0) {
            const { Responses } = await docClient.send(new BatchGetCommand({
                RequestItems: { [HIRING_CODING_TESTS_TABLE]: { Keys: codingTestKeys, ProjectionExpression: "codingTestId, title" } }
            }));
            (Responses[HIRING_CODING_TESTS_TABLE] || []).forEach(t => testMap.set(t.codingTestId, t.title));
        }
        console.log(`[GET /api/hiring/jobs/${jobId}/applications] Fetched ${testMap.size} unique test definitions.`);
        const testHeaders = Array.from(testMap.values()); // These are the names for the table columns

        // --- 6. Correlate Data ---
        // Group assignments by student email
        const assignmentsByEmail = assignments.reduce((acc, assign) => {
            if (!acc[assign.studentEmail]) acc[assign.studentEmail] = [];
            acc[assign.studentEmail].push(assign);
            return acc;
        }, {});

        // Build the final, enriched applicant list
        const enrichedApplicants = applications.map(app => {
            const applicantAssignments = assignmentsByEmail[app.email] || [];
            const scores = {};

            // For every test that was assigned for this job...
            testMap.forEach((testTitle, testId) => {
                // Find if this applicant was assigned this specific test
                const assignment = applicantAssignments.find(a => a.testId === testId);
                
                if (assignment) {
                    // They were assigned. Did they complete it?
                    const result = resultMap.get(assignment.assignmentId);
                    if (result) {
                        // Yes, they completed it.
                        // Format score: Aptitude is %, Coding is score/total
                        const score = (result.testType === 'aptitude') ? `${result.score}%` : `${result.score}/${result.totalMarks}`;
                        scores[testTitle] = score;
                    } else {
                        // No, they were assigned but did not attempt.
                        scores[testTitle] = "Not Attempted";
                    }
                } else {
                    // They were not assigned this test.
                    scores[testTitle] = "N/A";
                }
            });
            
            return {
                ...app,
                scores: scores // Attach the new scores object
            };
        });

        // Sort by applied date
        enrichedApplicants.sort((a, b) => new Date(b.appliedAt) - new Date(a.appliedAt));

        console.log(`[GET /api/hiring/jobs/${jobId}/applications] Sending ${enrichedApplicants.length} enriched applicants and ${testHeaders.length} test headers.`);
        res.json({
            jobTitle: job.title,
            applications: enrichedApplicants,
            testHeaders: testHeaders // Send the test names for the frontend to build the table
        });

    } catch (error) {
        console.error(`[GET /api/hiring/jobs/${jobId}/applications] Error:`, error);
        res.status(500).json({ message: 'Server error fetching applications.' });
    }
});


// HIRING MODERATOR: Bulk update application status and send email
app.post('/api/hiring/applications/update-status', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Hiring Moderator') return res.status(403).json({ message: 'Access denied.' });

    const { applicationIds, newStatus, emailDetails } = req.body;

    try {
        let emailsToSend = [];
        for (const appId of applicationIds) {
            const { Item: application } = await docClient.send(new GetCommand({ TableName: HIRING_TABLE, Key: { email: appId }}));
            
            await docClient.send(new UpdateCommand({
                TableName: HIRING_TABLE,
                Key: { email: appId },
                UpdateExpression: "set #s = :newStatus",
                ExpressionAttributeNames: { "#s": "status" },
                ExpressionAttributeValues: { ":newStatus": newStatus }
            }));
            if (application) emailsToSend.push(application.applicantEmail);
        }

        if (emailDetails && emailsToSend.length > 0) {
            const mailOptions = {
                to: emailsToSend,
                subject: emailDetails.subject,
                html: emailDetails.body
            };
           await sendEmailWithSES(mailOptions);
        }
        res.json({ message: `Successfully updated ${applicationIds.length} applicants to "${newStatus}".` });

    } catch (error) {
        console.error("Update Status Error:", error);
        res.status(500).json({ message: 'Server error updating status.' });
    }
});


// PUBLIC: Send OTP for checking application status
app.post('/api/public/check-status/send-otp', async (req, res) => {
    const { email } = req.body;
    // (Using the existing otpStore from your main file)
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[email.toLowerCase()] = { otp, expirationTime: Date.now() + 5 * 60 * 1000 };

    const mailOptions = {
        to: email,
        subject: 'Your Application Status Verification Code',
        html: `<p>Your code is: <b>${otp}</b>. It expires in 5 minutes.</p>`
    };
    try {
       await sendEmailWithSES(mailOptions);
        res.json({ message: 'Verification code sent to your email.' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to send OTP.' });
    }
});

// PUBLIC: Verify OTP and get application statuses
app.post('/api/public/check-status/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    const emailLower = email.toLowerCase();
    
    const storedOtp = otpStore[emailLower];
    if (!storedOtp || storedOtp.otp !== otp || Date.now() > storedOtp.expirationTime) {
        return res.status(400).json({ message: 'Invalid or expired code.' });
    }
    delete otpStore[emailLower]; // Use OTP once

    try {
         const { Items } = await docClient.send(new ScanCommand({
            TableName: HIRING_TABLE,
            FilterExpression: "recordType = :type AND applicantEmail = :email",
            ExpressionAttributeValues: { ":type": "APPLICATION", ":email": email }
        }));
        
        // To get job titles, we need to fetch the corresponding jobs
        const jobIds = [...new Set(Items.map(item => item.jobId))];
        const jobKeys = jobIds.map(jobId => ({ email: jobId }));
        let jobs = [];
        if (jobKeys.length > 0) {
            const { Responses } = await docClient.send(new BatchGetCommand({ RequestItems: { [HIRING_TABLE]: { Keys: jobKeys } } }));
            jobs = Responses[HIRING_TABLE];
        }
        const jobTitleMap = new Map(jobs.map(job => [job.email, job.title]));

        const results = Items.map(app => ({
            jobTitle: jobTitleMap.get(app.jobId) || 'Unknown Job',
            status: app.status,
            appliedAt: app.appliedAt
        }));

        res.json(results);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching application status.' });
    }
});

app.get('/api/hiring/dashboard-data', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Hiring Moderator') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    try {
        // 1. Get all jobs created by the moderator
        const { Items: jobs } = await docClient.send(new ScanCommand({
            TableName: "TestifyTests",
            FilterExpression: "createdBy = :creator AND testType = :type",
            ExpressionAttributeValues: { ":creator": req.user.email, ":type": "job" }
        }));

        if (jobs.length === 0) {
            return res.json({
                stats: { totalJobs: 0, totalApplicants: 0, totalShortlisted: 0, totalInProgress: 0 },
                applicantsByJob: { labels: [], counts: [] },
                statusDistribution: { labels: [], counts: [] }
            });
        }

        // 2. Get all applications for those jobs
        const jobIds = jobs.map(j => j.testId);
        const filterExpression = jobIds.map((_, i) => `:jid${i}`).join(', ');
        const expressionAttributeValues = jobIds.reduce((acc, id, i) => ({ ...acc, [`:jid${i}`]: id }), {});

        const { Items: applications } = await docClient.send(new ScanCommand({
            TableName: "TestifyResults",
            FilterExpression: `testId IN (${filterExpression})`,
            ExpressionAttributeValues: expressionAttributeValues
        }));
        
        // 3. Calculate Stats
        const totalJobs = jobs.length;
        const totalApplicants = applications.length;
        const totalShortlisted = applications.filter(a => a.status === 'Shortlisted').length;
        const totalInProgress = applications.filter(a => a.status && (a.status.includes('Round') || a.status === 'In Progress')).length;
        
        // 4. Calculate Chart Data: Applicants by Job
        const jobTitleMap = new Map(jobs.map(j => [j.testId, j.title]));
        const applicantsByJobCounts = applications.reduce((acc, app) => {
            const title = jobTitleMap.get(app.testId) || 'Unknown Job';
            acc[title] = (acc[title] || 0) + 1;
            return acc;
        }, {});
        
        // 5. Calculate Chart Data: Status Distribution
        const statusCounts = applications.reduce((acc, app) => {
            const status = app.status || 'Applied';
            acc[status] = (acc[status] || 0) + 1;
            return acc;
        }, {});

        res.json({
            stats: { totalJobs, totalApplicants, totalShortlisted, totalInProgress },
            applicantsByJob: {
                labels: Object.keys(applicantsByJobCounts),
                counts: Object.values(applicantsByJobCounts)
            },
            statusDistribution: {
                labels: Object.keys(statusCounts),
                counts: Object.values(statusCounts)
            }
        });

    } catch (error) {
        console.error("Get Dashboard Data Error:", error);
        res.status(500).json({ message: 'Server error fetching dashboard data.' });
    }
});

app.get('/api/public/jobs/:jobId', async (req, res) => {
    const { jobId } = req.params;
    console.log(`Fetching public job details for jobId: ${jobId}`); // Log requested ID

    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: HIRING_JOBS_TABLE, // Correct table
            Key: { jobId: jobId }          // Correct key: assumes 'jobId' is the primary key
        }));

        // 1. Check if the job item was found
        if (!Item) {
             console.warn(`Job not found in ${HIRING_JOBS_TABLE} for jobId: ${jobId}`);
             // Specific message for not found
             return res.status(404).json({ message: 'Job details not found.' });
        }

        console.log(`Found job item:`, JSON.stringify(Item, null, 2)); // Log found item details

        // 2. Check the application deadline AFTER finding the item
        const deadline = new Date(Item.applicationDeadline);
        const now = new Date();
        console.log(`Comparing deadline (${deadline.toISOString()}) with current time (${now.toISOString()}) for job ${jobId}`); // Log time comparison

        if (deadline < now) {
            console.warn(`Job deadline passed for ${jobId}. Deadline: ${Item.applicationDeadline}`);
            // Specific message for expired jobs
            // Using 404 might be more consistent for the frontend logic expecting "not found or expired"
            return res.status(404).json({ message: 'This job opening has expired.' });
        }

        // 3. Return item details if found and active
        console.log(`Returning job details for ${jobId}`);
        // Send the full job item back
        res.json(Item);

    } catch (error) {
        console.error(`Get Public Job Details Error for jobId ${jobId}:`, error);
        // Ensure a response is always sent in case of error
        if (!res.headersSent) {
             res.status(500).json({ message: 'Server error fetching job details.' });
        }
    }
});
app.get('/api/public/jobs/by-moderator/:moderatorId', async (req, res) => {
    const { moderatorId } = req.params;
    try {
        // Fetch the moderator's name for the page title
        const { Item: moderator } = await docClient.send(new GetCommand({
            TableName: "TestifyUsers",
            Key: { email: moderatorId }
        }));

        const moderatorName = moderator ? moderator.fullName : "Company";

        // Fetch all open jobs for this moderator
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyTests",
            FilterExpression: "createdBy = :creator AND testType = :type AND applicationDeadline > :now",
            ExpressionAttributeValues: {
                ":creator": moderatorId,
                ":type": "job",
                ":now": new Date().toISOString()
            }
        }));

        // Sort by creation date, newest first
        if (Items) {
            Items.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        }

        const jobs = Items ? Items.map(job => ({ ...job, jobId: job.testId })) : [];
        
        res.json({ jobs, moderatorName });
    } catch (error) {
        console.error("Get Public Jobs Error:", error);
        res.status(500).json({ message: 'Server error fetching jobs.' });
    }
});



// ** NEW ENDPOINT **
// HIRING MODERATOR: Update an existing job posting
app.put('/api/hiring/jobs/:jobId', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Hiring Moderator') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { jobId } = req.params;
    const { title, jd, eligibleColleges, applicationDeadline, hiringTimeline } = req.body;

    try {
        // First, verify the moderator owns this job
        const { Item: existingJob } = await docClient.send(new GetCommand({
            TableName: "TestifyTests",
            Key: { testId: jobId }
        }));

        if (!existingJob || existingJob.createdBy !== req.user.email) {
            return res.status(403).json({ message: 'You do not have permission to modify this job.' });
        }
        
        const updateExpression = "set title = :t, description = :d, eligibleColleges = :ec, applicationDeadline = :ad, hiringTimeline = :ht";
        const expressionAttributeValues = {
            ":t": title,
            ":d": jd,
            ":ec": eligibleColleges,
            ":ad": applicationDeadline,
            ":ht": hiringTimeline
        };

        await docClient.send(new UpdateCommand({
            TableName: "TestifyTests",
            Key: { testId: jobId },
            UpdateExpression: updateExpression,
            ExpressionAttributeValues: expressionAttributeValues,
        }));

        res.status(200).json({ message: 'Job updated successfully!' });
    } catch (error) {
        console.error("Update Job Error:", error);
        res.status(500).json({ message: 'Server error updating job.' });
    }
});


// ** NEW ENDPOINT **
// HIRING MODERATOR: Get all applicants for a specific job
app.get('/api/hiring/applicants/:jobId', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Hiring Moderator') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { jobId } = req.params;
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyResults",
            FilterExpression: "testId = :jobId", // Applications are stored with jobId in testId field
            ExpressionAttributeValues: { ":jobId": jobId }
        }));
        res.json(Items);
    } catch (error) {
        console.error("Get Applicants Error:", error);
        res.status(500).json({ message: 'Server error fetching applicants.' });
    }
});

// ** NEW ENDPOINT **
// HIRING MODERATOR: Update status for multiple applicants and optionally send email
app.post('/api/hiring/update-applicants-status', hiringModeratorAuth, async (req, res) => {
    // emailDetails will just be { send: true, status: "Shortlisted" } or null
    const { applicationIds, newStatus, emailDetails } = req.body; 
    
    if (!applicationIds || applicationIds.length === 0 || !newStatus) {
        return res.status(400).json({ message: 'Application IDs and new status are required.' });
    }

    try {
        // Step 1: Update all applicant statuses in the database
        const updatePromises = applicationIds.map(appId => {
            return docClient.send(new UpdateCommand({
                TableName: HIRING_APPLICATIONS_TABLE, // Your applications table
                Key: { applicationId: appId }, // The PK of that table
                UpdateExpression: "set #st = :s",
                ExpressionAttributeNames: { "#st": "status" },
                ExpressionAttributeValues: { ":s": newStatus }
            }));
        });
        
        await Promise.all(updatePromises);
        console.log(`[Status Update] Updated ${applicationIds.length} applicants to ${newStatus}.`);

        // Step 2: If emailDetails.send is true, fetch data and send emails
        if (emailDetails && emailDetails.send) {
            console.log("[Status Update] Sending email notifications...");
            
            // Fetch all the applications we just updated to get their details
            const keys = applicationIds.map(id => ({ applicationId: id }));
            const { Responses } = await docClient.send(new BatchGetCommand({
                RequestItems: { [HIRING_APPLICATIONS_TABLE]: { Keys: keys } }
            }));
            
            const applications = Responses[HIRING_APPLICATIONS_TABLE] || [];
            
            // Get unique Job IDs from these applications
            const jobIds = [...new Set(applications.map(app => app.jobId))];
            
            // Fetch all the corresponding jobs to get their titles
            const jobKeys = jobIds.map(id => ({ jobId: id })); // Assumes PK of jobs table is 'jobId'
            const { Responses: JobResponses } = await docClient.send(new BatchGetCommand({
                RequestItems: { [HIRING_JOBS_TABLE]: { Keys: jobKeys } } // Your jobs table
            }));

            const jobMap = new Map((JobResponses[HIRING_JOBS_TABLE] || []).map(job => [job.jobId, job.title]));

            // Loop through each application and send the dynamic, single-template email
            let emailsSent = 0;
            for (const app of applications) {
                const applicantName = app.firstName || 'Applicant';
                const jobTitle = jobMap.get(app.jobId) || 'the position you applied for';
                const status = newStatus; // The status you selected

                // The single, dynamic template
                const subject = `Your Application Status Update for: ${jobTitle}`;
                const body = `
                    <!doctype html>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Application Status Update</title>
</head>
<body style="margin:0;padding:0;background-color:#f5f7fa;font-family:Arial, Helvetica, sans-serif;color:#333;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f5f7fa;padding:24px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 6px 18px rgba(0,0,0,0.06);">
          
          <!-- Header / Logo -->
          <tr>
            <td style="padding:20px 24px;border-bottom:1px solid #eef0f2;">
              <table role="presentation" width="100%">
                <tr>
                  <td style="vertical-align:middle;">
                    <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1760086493/HireWithUS_wtn0pc.png" 
                         alt="HireWithUs" width="70" 
                         style="display:block;border:0;outline:none;text-decoration:none;">
                  </td>
                  <td style="text-align:right;vertical-align:middle;font-size:15px;color:#8b94a0;">
                    <span>Application Update</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:28px 32px 20px 32px;">
              <h2 style="margin:0 0 8px 0;font-size:20px;color:#222;">Dear ${applicantName},</h2>
              <p style="margin:0 0 16px 0;line-height:1.6;color:#555;font-size:15px;">
                We’re writing to update you regarding your application for the 
                <strong>${jobTitle}</strong> position.
              </p>

              <!-- Status Card -->
              <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;margin:16px 0 22px 0;">
                <tr>
                  <td style="padding:14px;border-radius:8px;background:#f7fbff;border:1px solid #e6f0ff;">
                    <strong style="display:block;font-size:15px;color:#0f1724;margin-bottom:6px;">Current Status</strong>
                    <span style="display:inline-block;padding:8px 12px;border-radius:999px;font-weight:600;font-size:13px;
                                 background:#fff3cd;color:#8a6d00;border:1px solid #ffe8a1;">
                      ${status}
                    </span>

                    <p style="margin:12px 0 0 0;color:#555;font-size:14px;line-height:1.55;">
                      We’ll reach out to you with further updates or next steps if necessary. 
                      Thank you for your interest and patience.
                    </p>
                  </td>
                </tr>
              </table>

              <!-- CTA Button -->
              <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="margin:12px 0 24px 0;">
                <tr>
                  <td align="center">
                    <a href="https://www.testify-lac.com/jobportal/student-login.html" 
                       target="_blank" 
                       style="background-color:#0069ff;color:#ffffff;text-decoration:none;padding:12px 24px;
                              border-radius:6px;display:inline-block;font-size:15px;font-weight:bold;">
                      View Application Status
                    </a>
                  </td>
                </tr>
              </table>

              <p style="margin:0;color:#666;font-size:14px;line-height:1.6;">
                Best regards,<br>
                <strong>The HireWithUs Team</strong>
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding:18px 32px 24px 32px;border-top:1px solid #eef0f2;background:#fbfdff;">
              <table role="presentation" width="100%">
                <tr>
                  <td style="font-size:13px;color:#7a8190;">
                    <strong style="color:#222;font-size:13px;">HireWithUs</strong><br>
                    <a href="mailto:support@testify-lac.com" style="color:#7a8190;text-decoration:none;">support@testify-lac.com</a>
                  </td>
                  <td style="text-align:right;vertical-align:middle;font-size:12px;color:#9aa0a6;">
                    <div>© 2025 HireWithUs</div>
                    <div style="margin-top:6px;">
                      <a href="#" style="color:#9aa0a6;text-decoration:underline;">Unsubscribe</a>
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

        </table>

        <!-- Mobile-friendly small footer note -->
        <div style="max-width:600px;margin-top:12px;font-size:12px;color:#939aa4;text-align:center;">
          This email was sent to you because you applied on our Job portal. 
          If you did not apply, please ignore this message.
        </div>
      </td>
    </tr>
  </table>
</body>
</html>

                `;

                try {
                    await sendEmailWithSES({
                        to: app.email,
                        subject: subject,
                        html: body
                    });
                    emailsSent++;
                } catch (emailError) {
                    console.error(`[Status Update] Failed to send email to ${app.email}:`, emailError);
                }
            }
            console.log(`[Status Update] Sent ${emailsSent} emails.`);
            return res.status(200).json({ message: `Successfully updated ${applicationIds.length} applicants to "${newStatus}" and sent ${emailsSent} emails.` });
        }

        // If not sending email
        res.status(200).json({ message: `Successfully updated ${applicationIds.length} applicants to "${newStatus}".` });

    } catch (error) {
        console.error("Update Applicant Status Error:", error);
        res.status(500).json({ message: 'Server error updating applicant status.' });
    }
});
app.post('/api/hiring/update-applicants-status', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Hiring Moderator') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    
    const { applicationIds, newStatus, emailDetails } = req.body;

    if (!applicationIds || applicationIds.length === 0 || !newStatus) {
        return res.status(400).json({ message: 'Application IDs and a new status are required.' });
    }

    try {
        // Batch update statuses
        for (const appId of applicationIds) {
            await docClient.send(new UpdateCommand({
                TableName: "TestifyResults",
                Key: { resultId: appId }, // Applications are in TestifyResults, keyed by resultId
                UpdateExpression: "set #st = :s",
                ExpressionAttributeNames: { "#st": "status" },
                ExpressionAttributeValues: { ":s": newStatus }
            }));
        }

        // Handle optional email sending
        if (emailDetails && emailDetails.send) {
            // Fetch the applications to get candidate emails
            const keys = applicationIds.map(id => ({ resultId: id }));
            const { Responses } = await docClient.send(new BatchGetCommand({
                RequestItems: { "TestifyResults": { Keys: keys } }
            }));
            
            const applications = Responses.TestifyResults || [];
            const emails = applications.map(app => app.candidateEmail);
            
            if (emails.length > 0) {
                const mailOptions = {
                    to: emails,
                    subject: emailDetails.subject,
                    html: emailDetails.body
                };
                await sendEmailWithSES(mailOptions);
            }
        }

        res.status(200).json({ message: `Successfully updated ${applicationIds.length} applicants to "${newStatus}".` });

    } catch (error) {
        console.error("Update Applicant Status Error:", error);
        res.status(500).json({ message: 'Server error updating applicant status.' });
    }
});

app.post('/api/public/applications/send-otp', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ message: 'Email is required.' });
    }
    const emailLower = email.toLowerCase();

    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyResults",
            FilterExpression: "candidateEmail = :email",
            ExpressionAttributeValues: { ":email": emailLower }
        }));

        if (!Items || Items.length === 0) {
            return res.status(404).json({ message: 'No applications found for this email address.' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expirationTime = Date.now() + 5 * 60 * 1000; 

        otpStore[emailLower] = { otp, expirationTime };
        console.log(`Generated application view OTP for ${email}: ${otp}`);

        const mailOptions = {
            to: email,
            subject: 'Your Application Status Verification Code',
            html: `<p>Your verification code is: <b>${otp}</b>. It expires in 5 minutes.</p>`
        };

       await sendEmailWithSES(mailOptions);
        res.status(200).json({ message: 'A verification code has been sent to your email.' });

    } catch (error) {
        console.error("Send App Status OTP Error:", error);
        res.status(500).json({ message: 'Server error. Please try again later.' });
    }
});

// PUBLIC: Verify OTP and fetch all applications for that email.
app.post('/api/public/applications/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) {
        return res.status(400).json({ message: 'Email and verification code are required.' });
    }
    const emailLower = email.toLowerCase();

    const storedOtpData = otpStore[emailLower];
    if (!storedOtpData || storedOtpData.otp !== otp || Date.now() > storedOtpData.expirationTime) {
        return res.status(400).json({ message: 'Invalid or expired verification code.' });
    }

    try {
        delete otpStore[emailLower];

        const { Items: applications } = await docClient.send(new ScanCommand({
            TableName: "TestifyResults",
            FilterExpression: "candidateEmail = :email",
            ExpressionAttributeValues: { ":email": emailLower }
        }));

        if (!applications || applications.length === 0) {
            return res.json([]);
        }

        const jobIds = [...new Set(applications.map(app => app.testId))];
        const keys = jobIds.map(jobId => ({ testId: jobId }));
        
        const { Responses } = await docClient.send(new BatchGetCommand({
            RequestItems: { "TestifyTests": { Keys: keys } }
        }));
        
        const jobs = Responses.TestifyTests || [];
        const jobInfoMap = new Map(jobs.map(j => [j.testId, { title: j.title, deadline: j.applicationDeadline }]));

        const enrichedApplications = applications.map(app => ({
            ...app,
            jobTitle: jobInfoMap.get(app.testId)?.title || 'Unknown Job',
            jobDeadline: jobInfoMap.get(app.testId)?.deadline || null
        }));

        enrichedApplications.sort((a, b) => new Date(b.appliedAt) - new Date(a.appliedAt));
        
        res.status(200).json(enrichedApplications);

    } catch (error) {
        console.error("Verify OTP & Fetch Apps Error:", error);
        res.status(500).json({ message: 'Server error fetching applications.' });
    }
});

// PUBLIC: Get a single application's details for editing
app.get('/api/public/application/:resultId', async (req, res) => {
    const { resultId } = req.params;
    try {
        const { Item: application } = await docClient.send(new GetCommand({
            TableName: "TestifyResults",
            Key: { resultId }
        }));

        if (!application) {
            return res.status(404).json({ message: "Application not found." });
        }

        const { Item: job } = await docClient.send(new GetCommand({
            TableName: "TestifyTests",
            Key: { testId: application.testId }
        }));

        if (!job) {
             return res.status(404).json({ message: "Associated job not found." });
        }
        
        if (new Date() > new Date(job.applicationDeadline)) {
            return res.status(403).json({ message: "The application deadline has passed. This application can no longer be edited." });
        }
        
        res.json({ ...application, jobTitle: job.title });

    } catch (error) {
        console.error("Get Single Application Error:", error);
        res.status(500).json({ message: 'Server error fetching application.' });
    }
});

// PUBLIC: Update an application before the deadline
app.put('/api/public/application/:resultId', async (req, res) => {
    const { resultId } = req.params;
    const { applicationData, rollNumber } = req.body;

    try {
        const { Item: application } = await docClient.send(new GetCommand({
            TableName: "TestifyResults",
            Key: { resultId }
        }));

        if (!application) {
            return res.status(404).json({ message: "Application not found." });
        }

        const { Item: job } = await docClient.send(new GetCommand({
            TableName: "TestifyTests",
            Key: { testId: application.testId }
        }));

        if (!job || new Date() > new Date(job.applicationDeadline)) {
            return res.status(403).json({ message: "The application deadline has passed." });
        }

        await docClient.send(new UpdateCommand({
            TableName: "TestifyResults",
            Key: { resultId },
            UpdateExpression: "set applicationData = :ad, rollNumber = :rn",
            ExpressionAttributeValues: {
                ":ad": applicationData,
                ":rn": rollNumber
            }
        }));

        res.status(200).json({ message: 'Your application has been updated successfully!' });

    } catch (error) {
        console.error("Update Application Error:", error);
        res.status(500).json({ message: 'Server error updating application.' });
    }
});

// Add this new endpoint to your backend.js file.
// It allows QuizCom Moderators to generate a quiz structure from text or a PDF file using AI.

app.post('/api/quizcom/generate-from-text', authMiddleware, quizModeratorAuth, upload.single('file'), async (req, res) => {
    let text = req.body.text;

    try {
        // If a file is uploaded, extract text from it (assuming PDF)
        if (req.file) {
            if (req.file.mimetype === 'application/pdf') {
                const data = await pdf(req.file.buffer);
                text = data.text;
            } else {
                return res.status(400).json({ message: 'Unsupported file type. Please upload a PDF.' });
            }
        }

        if (!text) {
            return res.status(400).json({ message: 'No text or file provided to generate the quiz.' });
        }

        // Use the Gemini API to generate the quiz content
        const fetch = (await import('node-fetch')).default;

        const prompt = `Based on the following text, create a complete, structured JSON object for a quiz. The JSON must have a 'title' (string) and an array of 'questions'. Each question object in the array must have:
- 'text' (string): The question text.
- 'type' (string): Can be 'single', 'multiple', or 'blank'.
- 'points' (number): Default to 10 if not specified.
- 'time' (number): Time in seconds, default to 30.
- 'options' (array of strings): For 'single' and 'multiple' choice types.
- 'correctAnswer' (string): For 'single' choice (the index of the correct option, e.g., "0") and 'blank' (the exact answer string).
- 'correctAnswers' (array of strings): For 'multiple' choice (an array of the indices of correct options, e.g., ["0", "2"]).
Here is the text to analyze:\n\n${text}`;

        const schema = {
            type: "OBJECT",
            properties: {
                "title": { "type": "STRING" },
                "questions": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "text": { "type": "STRING" },
                            "type": { "type": "STRING", "enum": ["single", "multiple", "blank"] },
                            "points": { "type": "NUMBER" },
                            "time": { "type": "NUMBER" },
                            "options": { "type": "ARRAY", "items": { "type": "STRING" } },
                            "correctAnswer": { "type": "STRING" },
                            "correctAnswers": { "type": "ARRAY", "items": { "type": "STRING" } }
                        },
                        "required": ["text", "type"]
                    }
                }
            },
            required: ["title", "questions"]
        };

        const apiKey = process.env.GEMINI_API_KEY || 'AIzaSyAR_X4MZ75vxwV7OTU3dabFRcVe4SxWpb8'; // It's better to use environment variables
        if (!apiKey) {
            return res.status(500).json({ message: "GEMINI_API_KEY is not configured on the server." });
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
        const structuredQuiz = JSON.parse(jsonText);

        res.json(structuredQuiz);

    } catch (error) {
        console.error('Error in AI quiz generation backend:', error);
        res.status(500).json({ message: 'Failed to generate quiz from AI.' });
    }
});


// =================================================================
// --- CERTIFICATE MODERATOR MANAGEMENT & ROUTES (NEW) ---
// =================================================================

// New authorization middleware for this specific role
const certificateModeratorAuth = (req, res, next) => {
    if (req.user.role !== 'Certificate Moderator' && req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied. Certificate Moderator or Admin role required.' });
    }
    next();
};

// ADMIN: Create a new certificate moderator account
app.post('/api/admin/certificate-moderators', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) {
        return res.status(400).json({ message: 'Full name, email, and password are required.' });
    }
    try {
        const existingUser = await docClient.send(new GetCommand({ TableName: "TestifyUsers", Key: { email: email.toLowerCase() } }));
        if (existingUser.Item) {
            return res.status(400).json({ message: 'An account with this email already exists.' });
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newModerator = {
            email: email.toLowerCase(),
            fullName,
            password: hashedPassword,
            role: "Certificate Moderator",
            isBlocked: false
        };
        await docClient.send(new PutCommand({ TableName: "TestifyUsers", Item: newModerator }));
        res.status(201).json({ message: 'Certificate Moderator account created successfully!' });
    } catch (error) {
        console.error("Create Certificate Moderator Error:", error);
        res.status(500).json({ message: 'Server error during account creation.' });
    }
});

// ADMIN: Get all certificate moderators
app.get('/api/admin/certificate-moderators', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyUsers",
            FilterExpression: "#role = :role",
            ExpressionAttributeNames: { "#role": "role" },
            ExpressionAttributeValues: { ":role": "Certificate Moderator" }
        }));
        res.json(Items.map(({ password, ...rest }) => rest)); // Exclude password from response
    } catch (error) {
        console.error("Get Certificate Moderators Error:", error);
        res.status(500).json({ message: 'Server error fetching accounts.' });
    }
});

// ADMIN: Delete a certificate moderator account
app.delete('/api/admin/certificate-moderators/:email', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: 'Access denied.' });
    try {
        await docClient.send(new DeleteCommand({ TableName: "TestifyUsers", Key: { email: req.params.email } }));
        res.json({ message: 'Account deleted successfully.' });
    } catch (error) {
        console.error("Delete Certificate Moderator Error:", error);
        res.status(500).json({ message: 'Server error deleting account.' });
    }
});


// IMPORTANT: The following endpoints REPLACE your existing certificate routes.
// Please remove the old ones from backend.js to avoid conflicts.

// CERT MODERATOR: Upload custom images
app.post('/api/certificate-moderator/upload-images', authMiddleware, certificateModeratorAuth, upload.array('images', 5), async (req, res) => {
    if (!req.files || req.files.length === 0) {
        return res.status(400).json({ message: 'No image files uploaded.' });
    }
    try {
        const uploadPromises = req.files.map(file => {
            const b64 = Buffer.from(file.buffer).toString("base64");
            const dataURI = "data:" + file.mimetype + ";base64," + b64;
            return cloudinary.uploader.upload(dataURI, { folder: "certificate_assets" });
        });
        const results = await Promise.all(uploadPromises);
        const imageUrls = results.map(result => result.secure_url);
        res.json({ message: 'Images uploaded successfully.', imageUrls });
    } catch (error) {
        console.error("Cert Image Upload Error:", error);
        res.status(500).json({ message: 'Server error uploading images.' });
    }
});


// CERT MODERATOR: Issue certificates (with image positions)
app.post('/api/certificate-moderator/issue-certificates', authMiddleware, certificateModeratorAuth, upload.single('studentDataSheet'), async (req, res) => {
    // customImages is now a JSON string of objects: '[{"url":"...", "x":100, "y":200}]'
    const { customImages } = req.body;
    const templateId = 'template_default'; // Using a single template as requested

    if (!req.file) {
        return res.status(400).json({ message: "Student data Excel sheet is required." });
    }

    try {
        const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });
        const sheetName = workbook.SheetNames[0];
        const studentData = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

        const issuanceBatchId = `batch_${uuidv4()}`;
        const imageDetails = customImages ? JSON.parse(customImages) : [];
        let issuedCount = 0;

        for (const student of studentData) {
            const studentEmail = student['Mail ID'];
            const studentName = student['Name of Student'];
            const eventName = student['Name of Event'];
            const rollNumber = student['Roll Number'];
            const eventDate = student['Date of Event Conducted'];

            if (!studentEmail || !studentName || !eventName) continue;

            const certificateId = uuidv4();
            const certificateItem = {
                issuanceBatchId,
                studentEmail: studentEmail.trim(),
                certificateId,
                templateId,
                studentName: studentName.trim(),
                eventName: eventName.trim(),
                rollNumber: String(rollNumber).trim(),
                eventDate: String(eventDate).trim(),
                customImages: imageDetails, // Save array of objects with positions
                issuedBy: req.user.email,
                issuedAt: new Date().toISOString()
            };

            await docClient.send(new PutCommand({
                TableName: "TestifyCertificateIssuance",
                Item: certificateItem
            }));

            const certificateLink = `https://testify-io-ai.onrender.com/view-certificate.html?id=${certificateId}`;
            const mailOptions = {
                to: studentEmail,
                subject: `Your Certificate for ${eventName}`,
                html: `<p>Congratulations, ${studentName}! Your certificate for ${eventName} is ready. View it here: <a href="${certificateLink}">${certificateLink}</a></p>`
            };
            
            await sendEmailWithSES(mailOptions);
            issuedCount++;
        }

        res.json({ message: `Process complete. Successfully issued ${issuedCount} certificates.` });
    } catch (error) {
        console.error("Issue Certificates Error:", error);
        res.status(500).json({ message: 'An unexpected error occurred.' });
    }
});


// CERT MODERATOR: Get issuance history
app.get('/api/certificate-moderator/issuance-history', authMiddleware, certificateModeratorAuth, async (req, res) => {
    try {
        // Fetch only batches created by the current moderator
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyCertificateIssuance",
            FilterExpression: "issuedBy = :email",
            ExpressionAttributeValues: { ":email": req.user.email }
        }));
        
        const batches = (Items || []).reduce((acc, cert) => {
            if (!acc[cert.issuanceBatchId]) {
                acc[cert.issuanceBatchId] = {
                    batchId: cert.issuanceBatchId,
                    issuedAt: cert.issuedAt,
                    eventName: cert.eventName,
                    studentCount: 0
                };
            }
            acc[cert.issuanceBatchId].studentCount++;
            return acc;
        }, {});

        const historyList = Object.values(batches).sort((a, b) => new Date(b.issuedAt) - new Date(a.issuedAt));
        res.json(historyList);
    } catch (error) {
        console.error("Get Issuance History Error:", error);
        res.status(500).json({ message: 'Server error fetching history.' });
    }
});

// PUBLIC Endpoint to fetch data for a single certificate page.
app.get('/api/public/certificate/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const { Items } = await docClient.send(new QueryCommand({
            TableName: "TestifyCertificateIssuance",
            IndexName: "CertificateIdIndex",
            KeyConditionExpression: "certificateId = :cid",
            ExpressionAttributeValues: { ":cid": id }
        }));

        if (!Items || Items.length === 0) {
            return res.status(404).json({ message: "Certificate not found. The ID may be invalid." });
        }
        
        // Return the first (and only) item found
        res.json(Items[0]);

    } catch (error) {
        console.error("Get Public Certificate Error:", error);
        res.status(500).json({ message: 'Server error retrieving certificate.' });
    }
});

app.post('/api/admin/quiz-moderators', authMiddleware, async (req, res) => {
    // Ensure only an Admin can create moderators
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }

    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) {
        return res.status(400).json({ message: 'Please provide full name, email, and password.' });
    }

    try {
        // Check if a user with this email already exists
        const { Item } = await docClient.send(new GetCommand({ TableName: "TestifyUsers", Key: { email: email.toLowerCase() } }));
        if (Item) {
            return res.status(400).json({ message: 'An account with this email already exists.' });
        }

        // Hash the password for security
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create the new user with the specific "QuizCom Moderator" role
        const newModerator = {
            email: email.toLowerCase(),
            fullName,
            password: hashedPassword,
            role: "QuizCom Moderator", // Assign the correct role
            isBlocked: false,
            createdAt: new Date().toISOString()
        };

        // Save the new moderator to the database
        await docClient.send(new PutCommand({ TableName: "TestifyUsers", Item: newModerator }));
        res.status(201).json({ message: 'QuizCom Moderator account created successfully!' });
    } catch (error) {
        console.error("Create QuizCom Moderator Error:", error);
        res.status(500).json({ message: 'Server error during account creation.' });
    }
});

// Get all QuizCom Moderators
app.get('/api/admin/quiz-moderators', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyUsers",
            FilterExpression: "#role = :role",
            ExpressionAttributeNames: { "#role": "role" },
            ExpressionAttributeValues: { ":role": "QuizCom Moderator" }
        }));
        // Send back the list of moderators, excluding their passwords
        res.json(Items.map(({ password, ...rest }) => rest));
    } catch (error) {
        console.error("Get QuizCom Moderators Error:", error);
        res.status(500).json({ message: 'Server error fetching accounts.' });
    }
});

// Delete a QuizCom Moderator
app.delete('/api/admin/quiz-moderators/:email', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { email } = req.params;
    try {
        await docClient.send(new DeleteCommand({
            TableName: "TestifyUsers",
            Key: { email }
        }));
        res.json({ message: 'QuizCom Moderator deleted successfully.' });
    } catch (error) {
        console.error("Delete QuizCom Moderator Error:", error);
        res.status(500).json({ message: 'Server error deleting account.' });
    }
});

app.post('/api/hiring/generate-test-from-pdf', authMiddleware, async (req, res) => {
    // Allow both Admin and Hiring Moderator roles
    if (req.user.role !== 'Admin' && req.user.role !== 'Hiring Moderator') {
        return res.status(403).json({ message: 'Access denied.' });
    }

    const { text } = req.body;
    if (!text) {
        return res.status(400).json({ message: 'No text provided from PDF.' });
    }

    try {
        // The logic here is identical to the admin endpoint, just with different authorization.
        const prompt = `Based on the following text which contains questions and answers, create a complete, structured JSON object for a test. The JSON must have a 'testTitle' (string), 'duration' (number, in minutes), 'totalMarks' (number), 'passingPercentage' (number), and an array of 'sections'. Each section must have a 'title' and an array of 'questions'. Each question object in the array must have:
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
                "sections": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "title": { "type": "STRING" },
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
                         "required": ["title", "questions"]
                    }
                }
            },
            required: ["testTitle", "duration", "totalMarks", "passingPercentage", "sections"]
        };

        const apiKey = 'AIzaSyAR_X4MZ75vxwV7OTU3dabFRcVe4SxWpb8'; // Use process.env in production

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
            console.error("Hiring Gemini API Error:", errorBody);
            throw new Error(`AI API call failed with status: ${apiResponse.status}`);
        }

        const result = await apiResponse.json();
        const jsonText = result.candidates[0].content.parts[0].text;
        const structuredTest = JSON.parse(jsonText);

        res.json(structuredTest);

    } catch (error) {
        console.error('Error in AI hiring test generation backend:', error);
        res.status(500).json({ message: 'Failed to generate test from AI.' });
    }
});


// job portal 


app.get('/api/public/colleges', async (req, res) => {
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: HIRING_COLLEGES_TABLE,
            ProjectionExpression: "collegeId, collegeName"
        }));
        const uniqueCollegesMap = new Map();
        (Items || []).forEach(item => {
            if (item.collegeName && !uniqueCollegesMap.has(item.collegeName.toLowerCase())) {
                uniqueCollegesMap.set(item.collegeName.toLowerCase(), item);
            }
        });
        const uniqueColleges = Array.from(uniqueCollegesMap.values());
        uniqueColleges.sort((a, b) => (a.collegeName || '').localeCompare(b.collegeName || '')); // Sort alphabetically
        res.json(uniqueColleges);
    } catch (error) {
        console.error("Get Public Colleges Error:", error);
        res.status(500).json({ message: 'Server error fetching colleges.' });
    }
});


app.post('/api/student/register', async (req, res) => {
    const { fullName, email, college, department, rollNumber, password } = req.body;

    // Basic validation
    if (!fullName || !email || !college || !department || !rollNumber || !password) {
        return res.status(400).json({ message: 'Please fill all fields.' });
    }

    try {
        const emailLower = email.toLowerCase();
        // Check if user already exists in the correct table
        const existingUser = await docClient.send(new GetCommand({
            TableName: HIRING_USERS_TABLE, // Using the correct table here for the check
            Key: { email: emailLower }
        }));
        if (existingUser.Item) {
            return res.status(400).json({ message: 'User with this email already exists.' });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create the new student object
        const newUser = {
            email: emailLower,
            fullName,
            college,
            department,
            rollNumber,
            password: hashedPassword,
            role: "Student",
            isBlocked: false,
            createdAt: new Date().toISOString()
        };

        // Save the new user to the correct table
        await docClient.send(new PutCommand({ 
            TableName: HIRING_USERS_TABLE, // << CORRECTED LINE
            Item: newUser 
        }));

        res.status(201).json({ message: 'Account created successfully! Redirecting to login...' });

    } catch (error) {
        console.error("Student Registration Error:", error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

app.post('/api/student/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Please provide email and password.' });
    try {
        const emailLower = email.toLowerCase();
        const { Item } = await docClient.send(new GetCommand({
            TableName: HIRING_USERS_TABLE,
            Key: { email: emailLower }
        }));
        if (!Item || Item.role !== 'Student') {
             return res.status(400).json({ message: 'Invalid credentials or not a student account.' });
        }
        if (Item.isBlocked) {
            return res.status(403).json({ message: 'Your account has been blocked.' });
        }
        const isMatch = await bcrypt.compare(password, Item.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        const payload = {
            user: { email: Item.email, fullName: Item.fullName, college: Item.college, role: Item.role }
        };
        jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' }, (err, token) => {
            if (err) throw err;
            const { password, ...userData } = Item;
            res.json({ message: 'Login successful!', token, user: userData });
        });
    } catch (error) {
        console.error("Student Login Error:", error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// Check Auth (General - used by frontend to verify token on page load)
app.get('/api/check-auth', authMiddleware, async (req, res) => {
    // authMiddleware already fetched and attached the user (excluding password) if valid
    res.json(req.user);
});
app.get('/api/student/jobs', studentAuthMiddleware, async (req, res) => {
    // Ensure req.user and req.user.college are populated by middleware
    if (!req.user || !req.user.college) {
        console.error("[STUDENT_JOBS_ERROR] Middleware failed: req.user or req.user.college missing.");
        return res.status(401).json({ message: "Authentication error or missing college information." });
    }
    const studentCollege = req.user.college;
    console.log(`[STUDENT_JOBS_START] Fetching eligible jobs for college: ${studentCollege}`);

    try {
        // 1. Scan for all currently open jobs
        console.log(`[STUDENT_JOBS_SCAN] Scanning ${HIRING_JOBS_TABLE} for open jobs.`);
        const { Items: allJobs } = await docClient.send(new ScanCommand({
            TableName: HIRING_JOBS_TABLE,
            FilterExpression: "applicationDeadline > :now", // Only fetch jobs whose deadline hasn't passed
            ExpressionAttributeValues: { ":now": new Date().toISOString() }
        }));
        console.log(`[STUDENT_JOBS_SCAN_RESULT] Found ${allJobs ? allJobs.length : 0} open jobs in total.`);


        // 2. Filter jobs based on student's college eligibility
        const eligibleJobs = (allJobs || []).filter(job =>
            job.eligibleColleges && // Check if eligibleColleges exists
            Array.isArray(job.eligibleColleges) && // Check if it's an array
            job.eligibleColleges.includes(studentCollege) // Check if student's college is included
        );
        console.log(`[STUDENT_JOBS_FILTER] Found ${eligibleJobs.length} jobs eligible for college: ${studentCollege}`);

        if (eligibleJobs.length === 0) {
            console.log(`[STUDENT_JOBS_INFO] No eligible jobs found for ${studentCollege}. Returning empty array.`);
            return res.json([]); // Return early if no jobs are eligible
        }

        // --- *** FIX IS HERE *** ---
        // 3. Get unique moderator emails from the eligible jobs
        const moderatorEmails = [...new Set(eligibleJobs.map(job => job.createdBy).filter(Boolean))]; 
        console.log(`[STUDENT_JOBS_MODERATORS] Found ${moderatorEmails.length} unique moderator emails: ${moderatorEmails.join(', ')}`);

        let moderatorMap = new Map();
        if (moderatorEmails.length > 0) {
            // 4. Fetch moderator details from the correct table: "TestifyUsers"
            const keys = moderatorEmails.map(email => ({ email: email })); 
            console.log(`[STUDENT_JOBS_BATCH_GET] Fetching details for ${keys.length} moderators from TestifyUsers`); // <<< CORRECTED TABLE NAME IN LOG

            const batchGetParams = {
                RequestItems: {
                    // *** THIS IS THE FIX ***
                    // Was: [HIRING_USERS_TABLE] (student table)
                    // Now: "TestifyUsers" (admin/moderator table)
                    "TestifyUsers": { 
                        Keys: keys,
                        ProjectionExpression: "email, fullName"
                    }
                }
            };

            const { Responses } = await docClient.send(new BatchGetCommand(batchGetParams));

            // *** THIS IS THE FIX ***
            // Read from the correct response object
            const moderators = Responses && Responses["TestifyUsers"] ? Responses["TestifyUsers"] : [];

            if (moderators.length > 0) {
                 moderators.forEach(mod => {
                     if (mod && mod.email) {
                         moderatorMap.set(mod.email, mod.fullName);
                     }
                 });
                 console.log(`[STUDENT_JOBS_BATCH_GET_SUCCESS] Successfully fetched details for ${moderators.length} moderators.`);
             } else {
                console.warn(`[STUDENT_JOBS_BATCH_GET_WARN] BatchGet returned no moderator details from TestifyUsers.`);
             }
        } else {
            console.log(`[STUDENT_JOBS_INFO] No moderator emails found in eligible jobs, skipping BatchGet.`);
        }
        // --- *** END OF FIX *** ---

        // 5. Format the jobs for the frontend, adding the moderator's name as 'postedBy'
        const formattedJobs = eligibleJobs.map(job => ({
            ...job,
            // This will now correctly find the fullName from the moderatorMap
            postedBy: moderatorMap.get(job.createdBy) || 'Company' // Fallback to 'Company'
        }));

        // 6. Sort jobs by creation date (newest first)
        formattedJobs.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        console.log(`[STUDENT_JOBS_SUCCESS] Returning ${formattedJobs.length} formatted and sorted jobs for ${studentCollege}.`);

        res.json(formattedJobs);

    } catch (error) {
        console.error(`[STUDENT_JOBS_FATAL_ERROR] Failed fetching jobs for student ${req.user.email} (College: ${studentCollege}):`, error);
        if (!res.headersSent) {
            res.status(500).json({ message: 'Server error fetching jobs. Please try again later or contact support.' });
        } else {
             console.error("[STUDENT_JOBS_ERROR] Headers already sent, could not send error response.");
        }
    }
});

app.get('/api/student/applications', studentAuthMiddleware, async (req, res) => {
    const studentEmail = req.user.email;
    try {
        const { Items } = await docClient.send(new QueryCommand({
            TableName: HIRING_APPLICATIONS_TABLE, IndexName: "email-index",
            KeyConditionExpression: "email = :email", ExpressionAttributeValues: { ":email": studentEmail }
        }));
        if (!Items || Items.length === 0) return res.json([]);
        // Fetch job deadlines
        const jobIds = [...new Set(Items.map(app => app.jobId))];
        const keys = jobIds.map(jobId => ({ jobId }));
        let jobDeadlineMap = new Map();
        if(keys.length > 0) {
            const { Responses } = await docClient.send(new BatchGetCommand({ RequestItems: { [HIRING_JOBS_TABLE]: { Keys: keys } } }));
            (Responses[HIRING_JOBS_TABLE] || []).forEach(j => jobDeadlineMap.set(j.jobId, j.applicationDeadline));
        }
        const enrichedApps = Items.map(app => ({ ...app, jobDeadline: jobDeadlineMap.get(app.jobId) || null }));
        enrichedApps.sort((a, b) => new Date(b.appliedAt) - new Date(a.appliedAt));
        res.json(enrichedApps);
    } catch (error) {
        console.error("Get Student Apps Error:", error);
        res.status(500).json({ message: 'Server error fetching applications.' });
    }
});
app.get('/api/student/applications/:applicationId', studentAuthMiddleware, async (req, res) => {
    const { applicationId } = req.params;
    const studentEmail = req.user.email;
    try {
        const { Item: application } = await docClient.send(new GetCommand({ TableName: HIRING_APPLICATIONS_TABLE, Key: { applicationId } }));
        if (!application || application.email !== studentEmail) {
            return res.status(404).json({ message: "Application not found or access denied." });
        }
        // Fetch job for deadline check
        const { Item: job } = await docClient.send(new GetCommand({ TableName: HIRING_JOBS_TABLE, Key: { jobId: application.jobId } }));
        const isEditable = job && new Date() < new Date(job.applicationDeadline);
        // Important: Only return isEditable if the deadline hasn't passed.
        // If it HAS passed, the PUT endpoint will reject the update anyway.
        res.json({ ...application, jobTitle: job?.title || 'Job Not Found', isEditable: isEditable });
    } catch (error) {
        console.error("Get Student App Error:", error);
        res.status(500).json({ message: 'Server error fetching application.' });
    }
});

// const uploadToCloudinary = async (file) => {
//     console.log(`[uploadToCloudinary] Attempting to upload file for field: ${file.fieldname}, mimetype: ${file.mimetype}`);
//     try {
//         const b64 = Buffer.from(file.buffer).toString("base64");
//         const dataURI = `data:${file.mimetype};base64,${b64}`;
//         const result = await cloudinary.uploader.upload(dataURI, {
//             folder: "job_applications",
//             resource_type: "auto"
//         });
//         console.log(`[uploadToCloudinary] SUCCESS for field: ${file.fieldname}. URL: ${result.secure_url}`);
//         return result;
//     } catch (error) {
//         console.error(`[uploadToCloudinary] FAILED for field: ${file.fieldname}. Error:`, error);
//         throw error;
//     }
// };

app.put('/api/student/applications/:applicationId', studentAuthMiddleware, upload.any(), async (req, res) => {
    const { applicationId } = req.params;
    // Ensure req.user is populated by studentAuthMiddleware
    if (!req.user || !req.user.email) {
        console.error("[APP_UPDATE_ERROR] Middleware failed: req.user not populated.");
        return res.status(401).json({ message: "Authentication error: User details missing." });
    }
    const studentEmail = req.user.email;
    console.log(`[APP_UPDATE_START] User ${studentEmail} attempting to update application ${applicationId}`);

    // Extract text fields from the request body
    const {
        firstName, lastName, phone, department, rollNumber, // Added department, rollNumber
        coverLetter, linkedinUrl, githubUrl, portfolioUrl,
        education, // JSON string for education array
        experiences, // JSON string for experience array
        // *** NEW: Add certifications, address, extracurricular ***
        certifications,
        address,
        extracurricular,
        govtIdType,
        // *** NEW *** Add fields to track existing file URLs if frontend sends them
        existingPassportPhotoUrl,
        existingResumeUrl,
        existingGovtIdUrl
    } = req.body;
     console.log("[APP_UPDATE_BODY] Received Text Body:", req.body);
     console.log("[APP_UPDATE_FILES] Received Files:", req.files ? req.files.map(f => f.fieldname) : 'None');


    try {
        // --- 1. Fetch the existing application ---
        console.log(`[APP_UPDATE_FETCH_APP] Fetching application ${applicationId} from ${HIRING_APPLICATIONS_TABLE}`);
        const { Item: application } = await docClient.send(new GetCommand({
            TableName: HIRING_APPLICATIONS_TABLE, // FIX: Use correct constant
            Key: { applicationId }
        }));

        // --- 2. Verify ownership and existence ---
        if (!application) {
            console.warn(`[APP_UPDATE_ERROR] Application ${applicationId} not found.`);
            return res.status(404).json({ message: "Application not found." });
        }
        if (application.email !== studentEmail) {
            console.warn(`[APP_UPDATE_AUTH_FAIL] Student ${studentEmail} attempted update on application ${applicationId} owned by ${application.email}`);
            return res.status(403).json({ message: "You are not authorized to update this application." });
        }
        console.log(`[APP_UPDATE_AUTH_PASS] Ownership verified for ${applicationId}.`);

        // --- 3. Fetch the associated job and verify the deadline ---
        console.log(`[APP_UPDATE_FETCH_JOB] Fetching job ${application.jobId} from ${HIRING_JOBS_TABLE}`);
        const { Item: job } = await docClient.send(new GetCommand({
            TableName: HIRING_JOBS_TABLE,       // FIX: Use correct constant
            Key: { jobId: application.jobId } // FIX: Use correct primary key 'jobId'
        }));

        if (!job) {
             console.error(`[APP_UPDATE_ERROR] Associated job ${application.jobId} not found for application ${applicationId}. Cannot verify deadline.`);
             return res.status(404).json({ message: "Associated job opening not found. Cannot verify deadline." });
        }
         console.log(`[APP_UPDATE_FETCH_JOB_SUCCESS] Job ${application.jobId} found. Deadline: ${job.applicationDeadline}`);

        if (new Date() > new Date(job.applicationDeadline)) {
             console.warn(`[APP_UPDATE_ERROR] Deadline passed for job ${application.jobId}. Cannot update application ${applicationId}.`);
            return res.status(403).json({ message: "The application deadline has passed. Cannot update." });
        }
         console.log(`[APP_UPDATE_DEADLINE_PASS] Deadline check passed for job ${application.jobId}.`);


        // --- 4. Process *all* file uploads *once* and store URLs in a map ---
        const files = req.files || [];
        const uploadedFileUrls = new Map(); // Use a Map to store { fieldname: url }
        console.log(`[APP_UPDATE_UPLOAD] Processing ${files.length} potential file uploads.`);

        // --- FIX: Initialize dynamic file maps ---
        const educationCertificates = {};
        const experienceCertificates = {};
        const certificationFiles = {};

        await Promise.all(files.map(async (file) => {
            try {
                const result = await uploadToCloudinary(file); // Ensure this helper exists and works
                
                // --- FIX: Handle ALL file types ---
                if (file.fieldname === 'passportPhoto' || file.fieldname === 'resume' || file.fieldname === 'govtId') {
                    uploadedFileUrls.set(file.fieldname, result.secure_url);
                } else if (file.fieldname.startsWith('education_certificate_')) {
                    const index = file.fieldname.split('_')[2];
                    educationCertificates[index] = result.secure_url;
                } else if (file.fieldname.startsWith('experience_certificate_')) {
                    const index = file.fieldname.split('_')[2];
                    experienceCertificates[index] = result.secure_url;
                } else if (file.fieldname.startsWith('certification_file_')) {
                    const index = file.fieldname.split('_')[2];
                    certificationFiles[index] = result.secure_url;
                }
                // --- End Fix ---

                console.log(`[APP_UPDATE_UPLOAD_SUCCESS] Field '${file.fieldname}' uploaded. URL: ${result.secure_url}`);
            } catch (uploadError) {
                console.error(`[APP_UPDATE_UPLOAD_FAIL] Cloudinary upload failed for field '${file.fieldname}':`, uploadError.message);
            }
        }));
        console.log(`[APP_UPDATE_UPLOAD_DONE] Processed file uploads. ${uploadedFileUrls.size + Object.keys(educationCertificates).length + Object.keys(experienceCertificates).length + Object.keys(certificationFiles).length} successful.`);


        // --- 5. Prepare the update payload (start with existing application data) ---
        let updateExpressionParts = [];
        const expressionAttributeValues = {};
        const expressionAttributeNames = {}; // Needed if attribute names conflict with DynamoDB keywords

        // Update basic text fields if they are provided in the request
        if (firstName !== undefined) { updateExpressionParts.push("firstName = :fn"); expressionAttributeValues[":fn"] = firstName; }
        if (lastName !== undefined) { updateExpressionParts.push("lastName = :ln"); expressionAttributeValues[":ln"] = lastName; }
        if (phone !== undefined) { updateExpressionParts.push("phone = :ph"); expressionAttributeValues[":ph"] = phone; }
        if (department !== undefined) { updateExpressionParts.push("department = :dept"); expressionAttributeValues[":dept"] = department; }
        if (rollNumber !== undefined) { updateExpressionParts.push("rollNumber = :rn"); expressionAttributeValues[":rn"] = rollNumber; }
        if (extracurricular !== undefined) { updateExpressionParts.push("extracurricular = :ext"); expressionAttributeValues[":ext"] = extracurricular; }
        if (coverLetter !== undefined) { updateExpressionParts.push("coverLetter = :cl"); expressionAttributeValues[":cl"] = coverLetter; }


        // Update nested link fields
         if (linkedinUrl !== undefined || githubUrl !== undefined || portfolioUrl !== undefined) {
             updateExpressionParts.push("#links = :links"); // Use #links because 'links' could be a reserved word
             expressionAttributeNames["#links"] = "links";
             expressionAttributeValues[":links"] = {
                 linkedin: linkedinUrl !== undefined ? linkedinUrl : application.links?.linkedin,
                 github: githubUrl !== undefined ? githubUrl : application.links?.github,
                 portfolio: portfolioUrl !== undefined ? portfolioUrl : application.links?.portfolio
             };
         }
         
        // Update address object
        if (address !== undefined) {
            try {
                const addressData = JSON.parse(address || '{}');
                updateExpressionParts.push("address = :addr");
                expressionAttributeValues[":addr"] = addressData;
            } catch (parseError) {
                 console.error(`[APP_UPDATE_PARSE_ERROR] Invalid JSON for address on application ${applicationId}:`, parseError.message);
                 return res.status(400).json({ message: "Invalid format for address data." });
            }
        }


        // Update single file URLs
        if (uploadedFileUrls.has('passportPhoto')) {
            updateExpressionParts.push("passportPhotoUrl = :p_photo");
            expressionAttributeValues[":p_photo"] = uploadedFileUrls.get('passportPhoto');
        } else if (existingPassportPhotoUrl !== undefined) {
            updateExpressionParts.push("passportPhotoUrl = :p_photo");
            expressionAttributeValues[":p_photo"] = existingPassportPhotoUrl || null;
        }

        if (uploadedFileUrls.has('resume')) {
            updateExpressionParts.push("resumeUrl = :res_url");
            expressionAttributeValues[":res_url"] = uploadedFileUrls.get('resume');
        } else if (existingResumeUrl !== undefined) {
            updateExpressionParts.push("resumeUrl = :res_url");
            expressionAttributeValues[":res_url"] = existingResumeUrl || null;
        }

        // Update Govt ID (Type and URL)
         if (govtIdType !== undefined || uploadedFileUrls.has('govtId') || existingGovtIdUrl !== undefined) {
             updateExpressionParts.push("govtId = :gid");
             expressionAttributeValues[":gid"] = {
                 type: govtIdType !== undefined ? govtIdType : application.govtId?.type,
                 url: uploadedFileUrls.get('govtId') || (existingGovtIdUrl !== undefined ? (existingGovtIdUrl || null) : application.govtId?.url)
             };
         }

        // --- 6. Update Education, Experience, & Certification Arrays ---
        try {
            if (education !== undefined) {
                const submittedEducation = JSON.parse(education || '[]');
                const updatedEducation = submittedEducation.map((edu, index) => {
                    const fieldName = `education_certificate_${index}`;
                    const certificateUrl = educationCertificates[index] || edu.certificateUrl || null;
                    return { ...edu, certificateUrl };
                });
                updateExpressionParts.push("education = :edu");
                expressionAttributeValues[":edu"] = updatedEducation;
            }

            if (experiences !== undefined) {
                const submittedExperiences = JSON.parse(experiences || '[]');
                const updatedExperiences = submittedExperiences.map((exp, index) => {
                    const fieldName = `experience_certificate_${index}`;
                    const certificateUrl = experienceCertificates[index] || exp.certificateUrl || null;
                    return { ...exp, certificateUrl };
                });
                 updateExpressionParts.push("experiences = :exp");
                 expressionAttributeValues[":exp"] = updatedExperiences;
            }

            if (certifications !== undefined) {
                const submittedCerts = JSON.parse(certifications || '[]');
                const updatedCerts = submittedCerts.map((cert, index) => {
                    const fieldName = `certification_file_${index}`;
                    const certificateUrl = certificationFiles[index] || cert.certificateUrl || null;
                    return { ...cert, certificateUrl };
                });
                updateExpressionParts.push("certifications = :certs");
                expressionAttributeValues[":certs"] = updatedCerts;
            }
        } catch (parseError) {
            console.error(`[APP_UPDATE_PARSE_ERROR] Invalid JSON for edu/exp/certs on application ${applicationId}:`, parseError.message);
            return res.status(400).json({ message: "Invalid format for education, experience, or certification data." });
        }


        // --- 7. Perform the update in DynamoDB using UpdateCommand ---
        if (updateExpressionParts.length === 0) {
             console.log(`[APP_UPDATE_NO_CHANGES] No fields provided for update for application ${applicationId}.`);
             return res.status(200).json({ message: 'No changes detected.' });
        }

        const updateParams = {
            TableName: HIRING_APPLICATIONS_TABLE, // FIX: Use correct constant
            Key: { applicationId },
            UpdateExpression: `SET ${updateExpressionParts.join(', ')}`,
            ExpressionAttributeValues: expressionAttributeValues,
            ReturnValues: "UPDATED_NEW"
        };
         if (Object.keys(expressionAttributeNames).length > 0) {
             updateParams.ExpressionAttributeNames = expressionAttributeNames;
         }

        console.log(`[APP_UPDATE_DB_PARAMS] Update Params for ${applicationId}:`, JSON.stringify(updateParams, null, 2));


        await docClient.send(new UpdateCommand(updateParams));

        console.log(`[APP_UPDATE_SUCCESS] Application ${applicationId} updated successfully.`);
        res.status(200).json({ message: 'Application updated successfully!' });

    } catch (error) {
        console.error(`[APP_UPDATE_FATAL_ERROR] Failed to update application ${applicationId}:`, error);
        let userMessage = 'Server error updating application. Please try again later.';
        let statusCode = 500;
        if (error.name === 'ValidationException') {
            userMessage = 'Database error: Invalid data format during update. Please contact support.';
        } else if (error.name === 'ResourceNotFoundException') {
             userMessage = 'Database error: Application table not found. Please contact support.';
        }
        if (!res.headersSent) {
            res.status(statusCode).json({ message: userMessage });
        }
    }
});

const uploadToCloudinary = (file) => {
    console.log(`[uploadToCloudinary] Attempting to upload file via STREAM: ${file.fieldname}, mimetype: ${file.mimetype}`);
    
    return new Promise((resolve, reject) => {
        // Create an upload stream
        const uploadStream = cloudinary.uploader.upload_stream(
            {
                folder: "job_applications",
                resource_type: 'auto' // This is key: Cloudinary will detect if it's an image, video, or raw file (like PDF)
            },
            (error, result) => {
                if (error) {
                    console.error(`[uploadToCloudinary] FAILED for field: ${file.fieldname}. Error:`, error);
                    return reject(new Error(error.message));
                }
                if (result) {
                    console.log(`[uploadToCloudinary] SUCCESS for field: ${file.fieldname}. URL: ${result.secure_url}`);
                    resolve(result);
                } else {
                    // This case should not happen if error is null, but as a safeguard
                    reject(new Error("Cloudinary upload failed with no result and no error."));
                }
            }
        );

        // Create a readable stream from the file buffer and pipe it to Cloudinary
        const bufferStream = new stream.PassThrough();
        bufferStream.end(file.buffer);
        bufferStream.pipe(uploadStream);
    });
};

const uploadToS3 = (file) => {
    console.log(`[uploadToS3] Attempting to upload: ${file.fieldname}, mimetype: ${file.mimetype}`);
    // Create a unique file key (path in S3)
    const fileKey = `job_applications/${uuidv4()}-${file.originalname.replace(/\s+/g, '_')}`;

    const params = {
        Bucket: S3_BUCKET_NAME, // Use the bucket you specified
        Key: fileKey,
        Body: file.buffer,
        ContentType: file.mimetype,
    };

    return new Promise(async (resolve, reject) => {
        try {
            await s3Client.send(new PutObjectCommand(params));
            // Construct the public URL
            const url = `https://${S3_BUCKET_NAME}.s3.${AWS_S3_REGION}.amazonaws.com/${fileKey}`;
            console.log(`[uploadToS3] SUCCESS for field: ${file.fieldname}. URL: ${url}`);
            resolve({ secure_url: url }); // Return in a format similar to Cloudinary's
        } catch (error) {
            console.error(`[uploadToS3] FAILED for field: ${file.fieldname}. Error:`, error);
            reject(error);
        }
    });
};
const STUDENT_PHOTOS_BUCKET = process.env.STUDENT_PHOTOS_BUCKET || "hirewithusinterviewphotos"; // e.g., hirewithus-student-photos

app.post('/api/student/apply/:jobId', studentAuthMiddleware, upload.any(), async (req, res) => {
    const { jobId } = req.params;
    // Ensure req.user is populated by studentAuthMiddleware
    if (!req.user || !req.user.email) {
        console.error("[APPLY_ERROR] studentAuthMiddleware did not populate req.user correctly.");
        return res.status(401).json({ message: "Authentication error: User details missing." });
    }
    const studentEmail = req.user.email; // Get email from authenticated user
    const studentCollege = req.user.college; // Get college from authenticated user

    console.log(`[APPLY_START] Received application for job ${jobId} from student ${studentEmail}`);
    
    // Extract text fields from req.body
    const {
        firstName, lastName, phone, department, rollNumber, // Student profile info from form
        coverLetter, linkedinUrl, githubUrl, portfolioUrl, // Optional fields from form
        education, // JSON string for education array
        experiences, // JSON string for experience array
        certifications, // JSON string for certifications array
        address, // JSON string for address object
        govtIdType, // Govt ID Type
        extracurricular // Extracurricular activities
    } = req.body;

    // Basic validation for required text fields from the form
    if (!firstName || !lastName || !phone || !department || !rollNumber) {
        console.warn(`[APPLY_VALIDATION_FAIL] Missing required personal details for student ${studentEmail}, job ${jobId}.`);
        return res.status(400).json({ message: 'Missing required personal details (First Name, Last Name, Phone, Department, Roll Number).' });
    }
    console.log("[APPLY_VALIDATION_PASS] Required text fields present.");

    try {
        // --- 1. Fetch Job Details & Verify Eligibility ---
        console.log(`[APPLY_FETCH_JOB] Fetching job details for ${jobId}.`);
        const { Item: job } = await docClient.send(new GetCommand({
            TableName: HIRING_JOBS_TABLE, // Ensure this constant points to your jobs table ("HiringJobs")
            Key: { jobId: jobId }         // Ensure 'jobId' is the primary key name
        }));

        if (!job) {
            console.warn(`[APPLY_ERROR] Job ${jobId} not found.`);
            return res.status(404).json({ message: 'Job opening not found.' });
        }
        console.log(`[APPLY_FETCH_JOB_SUCCESS] Job ${jobId} found. Title: ${job.title}. Checking deadline and eligibility.`);

        // Check deadline
        const now = new Date();
        const deadline = new Date(job.applicationDeadline);
        if (deadline < now) {
            console.warn(`[APPLY_ERROR] Application deadline passed for job ${jobId}. Deadline: ${job.applicationDeadline}`);
            return res.status(400).json({ message: 'The application deadline has passed.' });
        }
        console.log(`[APPLY_DEADLINE_PASS] Deadline check passed.`);


        // Check if student's college is eligible
        if (!studentCollege) {
            console.warn(`[APPLY_ERROR] Student ${studentEmail} college information is missing in token/user data.`);
            return res.status(403).json({ message: 'Your college information is missing. Cannot verify eligibility.' });
        }
        if (!job.eligibleColleges || !Array.isArray(job.eligibleColleges) || !job.eligibleColleges.includes(studentCollege)) {
            console.warn(`[APPLY_ERROR] Student ${studentEmail} from college '${studentCollege}' is not eligible for job ${jobId}. Eligible: ${job.eligibleColleges?.join(', ')}`);
            return res.status(403).json({ message: `Your college ('${studentCollege}') is not eligible for this job.` });
        }
        console.log(`[APPLY_ELIGIBILITY_PASS] Student ${studentEmail} from '${studentCollege}' is eligible.`);

        // --- 2. Check if student already applied ---
    console.log(`[APPLY_CHECK_DUPLICATE] Checking if student ${studentEmail} already applied for job ${jobId}. Using index: email-jobId-index`);
        const queryParams = {
            TableName: HIRING_APPLICATIONS_TABLE, // Ensure this is "HiringApplications"
            IndexName: "email-jobId-index",      // Make sure this index exists with HASH(email), RANGE(jobId)
            KeyConditionExpression: "email = :email AND jobId = :jobId",
            ExpressionAttributeValues: { ":email": studentEmail, ":jobId": jobId },
            Limit: 1 // We only need to know if at least one exists
        };
        console.log("[APPLY_CHECK_DUPLICATE] Query Params:", queryParams);
        const { Items: existingApps } = await docClient.send(new QueryCommand(queryParams));

        if (existingApps && existingApps.length > 0) {
            console.warn(`[APPLY_ERROR] Duplicate application found for student ${studentEmail} and job ${jobId}.`);
            return res.status(400).json({ message: 'You have already applied for this job.' });
        }
        console.log(`[APPLY_CHECK_DUPLICATE_PASS] No existing application found.`);

        // --- 3. Process File Uploads (All files at once) ---
        const files = req.files || [];
        console.log(`[APPLY_UPLOAD] Processing ${files.length} files.`);

        let passportPhotoUrl = null;
        let resumeUrl = null;
        let govtIdUrl = null;
        const educationCertificates = {}; // To store { index: url }
        const experienceCertificates = {}; // To store { index: url }
        const certificationFiles = {}; // To store { index: url }

        const uploadPromises = files.map(async (file) => {
            try {
                // --- MODIFICATION: Call uploadToS3 ---
                const s3Url = await uploadToS3(file); // Use the new S3 uploader
                
                // Assign URL to the correct variable based on fieldname
                if (file.fieldname === 'passportPhoto') {
                    passportPhotoUrl = s3Url;
                } else if (file.fieldname === 'resume') {
                    resumeUrl = s3Url;
                } else if (file.fieldname === 'govtId') {
                    govtIdUrl = s3Url;
                } else if (file.fieldname.startsWith('education_certificate_')) {
                    const index = file.fieldname.split('_')[2];
                    educationCertificates[index] = s3Url;
                } else if (file.fieldname.startsWith('experience_certificate_')) {
                    const index = file.fieldname.split('_')[2];
                    experienceCertificates[index] = s3Url;
                } else if (file.fieldname.startsWith('certification_file_')) {
                    const index = file.fieldname.split('_')[2];
                    certificationFiles[index] = s3Url;
                }
                // --- END MODIFICATION ---
            } catch (uploadError) {
                console.error(`[APPLY_ERROR] S3 upload failed for field '${file.fieldname}':`, uploadError); // Modified log
                // We'll throw an error to stop the application process
                throw new Error(`Upload failed for file: ${file.originalname}. ${uploadError.message}`);
            }
        });

        await Promise.all(uploadPromises); // Wait for all files to upload
        console.log(`[APPLY_UPLOAD_DONE] All files processed via S3.`); // Modified log

        // Validate that required files were uploaded
        if (!resumeUrl) {
            console.warn(`[APPLY_ERROR] Resume file missing after processing uploads for student ${studentEmail}, job ${jobId}`);
            return res.status(400).json({ message: 'Resume file is required but was not received by the server.' });
        }
        if (!passportPhotoUrl) {
            console.warn(`[APPLY_ERROR] Passport photo missing after processing uploads for student ${studentEmail}, job ${jobId}`);
            return res.status(400).json({ message: 'Passport photo is required but was not received by the server.' });
        }

        // --- 4. Parse and Enrich JSON Data ---
        console.log("[APPLY_PARSE_JSON] Parsing JSON strings for education, experience, certs, address...");
        let educationData = [];
        let experienceData = [];
        let certificationData = [];
        let addressData = {};

        try {
            educationData = JSON.parse(education || '[]').map((edu, index) => ({
                ...edu,
                certificateUrl: educationCertificates[index] || null // Add the uploaded URL
            }));
            
            experienceData = JSON.parse(experiences || '[]').map((exp, index) => ({
                ...exp,
                certificateUrl: experienceCertificates[index] || null // Add the uploaded URL
            }));

            certificationData = JSON.parse(certifications || '[]').map((cert, index) => ({
                ...cert,
                certificateUrl: certificationFiles[index] || null // Add the uploaded URL
            }));
            
            addressData = JSON.parse(address || '{}');

        } catch (parseError) {
            console.error(`[APPLY_ERROR] Invalid JSON data submitted by ${studentEmail} for job ${jobId}:`, parseError.message);
            return res.status(400).json({ message: "Invalid format for education, experience, or address data." });
        }
            console.log("[APPLY_PARSE_JSON_SUCCESS] JSON data parsed and enriched.");


        // --- 5. Create and Save Application ---
        const applicationId = `sapp_${uuidv4()}`; // Prefix for student apps
        console.log(`[APPLY_CREATE_ITEM] Creating application item with ID ${applicationId}`);
        
        const newApplication = {
            applicationId, // Primary Key for HIRING_APPLICATIONS_TABLE
            jobId,         // Range Key for email-jobId-index, Sort Key for jobId-index
            jobTitle: job.title,
            
            // --- All data fields ---
            email: studentEmail,       // Partition Key for email-jobId-index
            college: studentCollege,
            firstName: firstName,
            lastName: lastName,
            phone: phone,
            department: department,
            rollNumber: rollNumber,
            
            passportPhotoUrl: passportPhotoUrl, // SAVED
            resumeUrl: resumeUrl,           // SAVED
            
            govtId: {                       // SAVED
                type: govtIdType || null,
                url: govtIdUrl || null
            },
            
            address: addressData,           // SAVED
            
            education: educationData,       // SAVED
            experiences: experienceData,    // SAVED
            certifications: certificationData, // SAVED
            
            extracurricular: extracurricular || null, // SAVED
            coverLetter: coverLetter || null,       // SAVED
            
            links: {                        // SAVED
                linkedin: linkedinUrl || null,
                github: githubUrl || null,
                portfolio: portfolioUrl || null
            },
            
            status: 'Applied', // Initial status
            appliedAt: new Date().toISOString() // Sort Key for jobId-index
        };

        console.log("[APPLY_CREATE_ITEM] Final Application Data:", JSON.stringify(newApplication, null, 2));


        console.log(`[APPLY_SAVE_DB] Attempting to save application ${applicationId} to ${HIRING_APPLICATIONS_TABLE}.`);
        await docClient.send(new PutCommand({
            TableName: HIRING_APPLICATIONS_TABLE, // Save to the correct Applications table ("HiringApplications")
            Item: newApplication
        }));

        console.log(`[APPLY_SUCCESS] Application ${applicationId} submitted successfully for job ${jobId} by ${studentEmail}`);
        res.status(201).json({ message: 'Application submitted successfully!' });

    } catch (error) {
        // Log the detailed error with more context
        console.error(`[APPLY_FATAL_ERROR] Endpoint failed for student ${studentEmail}, job ${jobId}:`);
        console.error("Error Message:", error.message);
        console.error("Error Name:", error.name);
        // Log specifics if it's an AWS error
        if (error.$metadata) {
            console.error("AWS Error Metadata:", error.$metadata);
        }
            console.error("Error Stack:", error.stack); // Log the full stack trace

        // Determine user message based on error type
        let userMessage = 'Server error submitting application. Please try again later.';
        let statusCode = 500;

        if (error.name === 'ValidationException') { // DynamoDB validation error
            userMessage = 'Database error: Invalid data format during submission. Please contact support.';
            statusCode = 500; // Or 400 if it's likely user input related, but often schema issues
        } else if (error.name === 'ResourceNotFoundException') { // DynamoDB table/index not found
            userMessage = 'Database error: Required table or index not found. Please contact support.';
            statusCode = 500;
        } else if (error.message.includes('IndexNotFound')) { // Specific index error check
            userMessage = 'Database index configuration error. Please contact support.';
            statusCode = 500;
        } else if (error.message.includes('upload') || error.message.includes('S3')) { // --- MODIFICATION: Check for S3 ---
            userMessage = `Server error during file upload: ${error.message}. Please ensure the file is valid and try again.`;
            statusCode = 500;
        } else if (error.message.includes('Token is not valid') || error.message.includes('authorization denied')) { // Auth errors
            userMessage = 'Authentication error. Please log in again.';
            statusCode = 401;
        }
        // Add more specific AWS SDK v3 error checks if needed (e.g., error.code)

        // Ensure headers aren't already sent before sending response
        if (!res.headersSent) {
            res.status(statusCode).json({ message: userMessage });
        } else {
            console.error("[APPLY_ERROR] Headers already sent, could not send error response to client.");
        }
    }
});

app.get('/api/public/problem-details/:problemId', authMiddleware, async (req, res) => {
    // 1. Basic Auth & Input Checks
    if (!req.user || !req.user.isExternal) {
        return res.status(403).json({ message: 'Access denied.' });
    }
    const { problemId } = req.params;
    const { testId: assignedTestId, assignmentId: tokenAssignmentId, email: candidateEmail, isMockTest } = req.user; // Get details from token

    if (!problemId || !assignedTestId || !tokenAssignmentId) {
        return res.status(400).json({ message: 'Missing required parameters (problemId, testId, assignmentId).' });
    }

    console.log(`[GET /problem-details] Request for problemId: ${problemId}, assignment: ${tokenAssignmentId}, isMock: ${isMockTest}`);

    try {
        // --- 2. Verify Assignment Validity (ONLY IF NOT a mock test) ---
        if (!isMockTest) {
            console.log(`[GET /problem-details] Standard Flow: Verifying assignment ${tokenAssignmentId} in ${HIRING_ASSIGNMENTS_TABLE}`);
            const { Item: assignment } = await docClient.send(new GetCommand({
                TableName: HIRING_ASSIGNMENTS_TABLE,
                Key: { assignmentId: tokenAssignmentId }
            }));

            if (!assignment || assignment.testId !== assignedTestId || assignment.studentEmail !== candidateEmail) {
                console.warn(`[GET /problem-details] Assignment ${tokenAssignmentId} invalid or mismatch.`);
                return res.status(403).json({ message: 'Assignment invalid or mismatch.' });
            }
            if (assignment.testType !== 'coding') {
                 console.warn(`[GET /problem-details] Assignment ${tokenAssignmentId} is not for a coding test (type: ${assignment.testType}).`);
                 return res.status(400).json({ message: 'Invalid test type for requesting coding problem details.' });
            }
            console.log(`[GET /problem-details] Assignment ${tokenAssignmentId} verified.`);
        } else {
            console.log(`[GET /problem-details] MOCK TEST flow: Bypassing assignment check for ${tokenAssignmentId}.`);
        }
        // --- END OF FIX ---


        // 3. Fetch the Coding Test Definition
        console.log(`[GET /problem-details] Fetching coding test definition ${assignedTestId} from ${HIRING_CODING_TESTS_TABLE}`);
        const { Item: codingTest } = await docClient.send(new GetCommand({
            TableName: HIRING_CODING_TESTS_TABLE,
            Key: { codingTestId: assignedTestId } // Use the correct PK name
        }));

        if (!codingTest) {
            console.error(`[GET /problem-details] Coding test definition ${assignedTestId} not found.`);
            return res.status(404).json({ message: 'Assigned coding test definition not found.' });
        }
        console.log(`[GET /problem-details] Found coding test definition: ${codingTest.title}`);


        // 4. Verify Problem Exists within Test Sections
        let problemFoundInTest = false;
        if (codingTest.sections && Array.isArray(codingTest.sections)) {
            console.log(`[GET /problem-details] Checking sections structure for problemId: ${problemId}`);
            for (const section of codingTest.sections) {
                if (section.problems && Array.isArray(section.problems)) {
                    if (section.problems.some(p => p.problemId === problemId)) {
                        problemFoundInTest = true;
                        console.log(`[GET /problem-details] Found problem ${problemId} in section "${section.title}" of test ${assignedTestId}.`);
                        break; // Exit loop once found
                    }
                }
            }
        } 
        // (You can add backwards compatibility for old 'problems' array if needed)

        if (!problemFoundInTest) {
            console.warn(`[GET /problem-details] Problem ${problemId} is NOT part of the assigned test ${assignedTestId}. Access denied.`);
            return res.status(403).json({ message: 'Problem is not part of the assigned test.' });
        }
        // --- End Modified Check ---


        // 5. Fetch the Full Problem Details
        console.log(`[GET /problem-details] Fetching full details for problem ${problemId} from ${HIRING_CODING_PROBLEMS_TABLE}`);
        const { Item: fullProblemData } = await docClient.send(new GetCommand({
            TableName: HIRING_CODING_PROBLEMS_TABLE, // Ensure this table name is correct
            Key: { problemId: problemId }           // Ensure 'problemId' is the correct primary key
        }));

        if (!fullProblemData) {
            console.error(`[GET /problem-details] Full problem details not found for problemId: ${problemId} in ${HIRING_CODING_PROBLEMS_TABLE}.`);
            return res.status(404).json({ message: 'Problem details not found.' });
        }
        console.log(`[GET /problem-details] Successfully fetched full details for problem ${problemId}.`);

        // 6. Return the full problem data
        res.json(fullProblemData);

    } catch (error) {
        console.error(`[GET /problem-details] Error fetching problem details for ${problemId} (Assignment: ${tokenAssignmentId}):`, error);
        if (error.name === 'ResourceNotFoundException') {
            console.error(`[GET /problem-details] Critical Error: A required table might be missing (${HIRING_ASSIGNMENTS_TABLE}, ${HIRING_CODING_TESTS_TABLE}, or ${HIRING_CODING_PROBLEMS_TABLE}).`);
        }
        res.status(500).json({ message: 'Server error fetching problem details.' });
    }
});
app.get('/api/candidate-details', authMiddleware, async (req, res) => {
    // ... (Keep the existing logic with GetCommand retries) ...
    if (!req.user || !req.user.email) { /* ... */ }
    const candidateEmail = req.user.email;
    const assignmentIdFromToken = req.user.assignmentId;
    if (!assignmentIdFromToken) { /* ... */ }

    console.log(`[GET /candidate-details] Request for email: ${candidateEmail}, Assignment ID: ${assignmentIdFromToken}`);
    const expectedResultId = `init_${assignmentIdFromToken}`;
    console.log(`[GET /candidate-details] Constructed expected resultId for GET: ${expectedResultId}`);

    try {
        let candidateData = null;
        const maxRetries = 2;
        const initialDelay = 300; // Slightly increased delay

        // --- Step 1: Attempt direct GetCommand (with retries) ---
        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            if (attempt > 0) {
                const delay = initialDelay * Math.pow(2, attempt - 1); // Exponential backoff (300ms, 600ms)
                console.log(`[GET /candidate-details] Retrying GetCommand (attempt ${attempt + 1}/${maxRetries + 1}) after ${delay}ms delay for resultId: ${expectedResultId}`);
                await new Promise(resolve => setTimeout(resolve, delay));
            }

            console.log(`[GET /candidate-details] Attempting direct GetCommand (attempt ${attempt + 1}) in ${HIRING_TEST_RESULTS_TABLE} for resultId: ${expectedResultId}`);
            try {
                // Use ConsistentRead for GetCommand here as well
                const getParams = { TableName: HIRING_TEST_RESULTS_TABLE, Key: { resultId: expectedResultId }, ConsistentRead: true };
                const { Item } = await docClient.send(new GetCommand(getParams));
                console.log(`[GET /candidate-details] Raw GetCommand response (attempt ${attempt + 1}):`, JSON.stringify({ Item }));

                if (Item && Item.candidateEmail === candidateEmail && Item.assignmentId === assignmentIdFromToken) {
                    candidateData = Item;
                    console.log(`[GET /candidate-details] Found matching 'init_' details record via GetCommand (attempt ${attempt + 1}).`);
                    break; // Exit the loop if found
                } else if (Item) {
                    console.warn(`[GET /candidate-details] GetCommand found record (attempt ${attempt + 1}), but email/assignmentId mismatch.`);
                } else {
                    console.log(`[GET /candidate-details] Direct GetCommand found no record (attempt ${attempt + 1}).`);
                }
            } catch (getError) {
                 console.error(`[GET /candidate-details] Error during GetCommand (attempt ${attempt + 1}):`, getError);
                 if (getError.name === 'ResourceNotFoundException') throw getError;
            }
        } // End of retry loop


        // --- Step 3: Process the found data (if GetCommand succeeded) ---
        if (candidateData) {
            const detailsToSend = {
                fullName: candidateData.fullName,
                rollNumber: candidateData.rollNumber,
                collegeName: candidateData.collegeName,
                department: candidateData.department,
                profileImageUrl: candidateData.profileImageUrl || null
            };
            if (!detailsToSend.fullName || !detailsToSend.rollNumber || !detailsToSend.collegeName || !detailsToSend.department) {
                console.warn(`[GET /candidate-details] Incomplete details extracted even though record was found. Data:`, candidateData);
                 return res.status(404).json({ message: 'Incomplete candidate details found in records.' });
            }
            console.log(`[GET /candidate-details] Sending details for ${candidateEmail}.`);
            res.json(detailsToSend);
        } else {
            console.warn(`[GET /candidate-details] FINAL: No valid candidate details record found for ${candidateEmail} (Assignment: ${assignmentIdFromToken}) after ${maxRetries + 1} GetCommand attempts.`);
            res.status(404).json({ message: 'Candidate details not found. Please ensure you completed any initial verification steps.' });
        }

    } catch (error) {
        console.error(`[GET /candidate-details] Outer catch block error for ${candidateEmail}:`, error);
        if (error.name === 'ResourceNotFoundException') {
             console.error(`[GET /candidate-details] Critical Error: DynamoDB table (${HIRING_TEST_RESULTS_TABLE}) might be missing or misspelled.`);
             return res.status(500).json({ message: `Server configuration error: Table not found.` });
        }
        res.status(500).json({ message: 'Server error fetching candidate details.' });
    }
});



app.post('/api/save-initial-details', authMiddleware, async (req, res) => {
    // ... (Keep existing validation for token and details) ...
    if (!req.user || !req.user.isExternal || !req.user.assignmentId) {
        console.warn('[SAVE DETAILS] Denied: Invalid token or missing assignmentId.');
        return res.status(403).json({ message: 'Invalid token or assignment reference.' });
    }
    const { assignmentId } = req.user;
    const { details } = req.body;
    if (!details || !details.fullName || !details.rollNumber || !details.collegeName || !details.department || !details.profileImageUrl) {
         console.warn(`[SAVE DETAILS] Incomplete details received for assignment ${assignmentId}. Body:`, req.body);
         return res.status(400).json({ message: 'Missing required candidate details: Full Name, Roll Number, College, Department, and Profile Image URL.' });
    }
    console.log(`[SAVE DETAILS] Request received for assignment: ${assignmentId}, Candidate: ${req.user.email}`);

    let assignment; // Define assignment variable outside the try block if needed later
    try {
        // --- Verify Assignment ---
        console.log(`[SAVE DETAILS] Verifying assignment ${assignmentId} in ${HIRING_ASSIGNMENTS_TABLE}`);
        const { Item } = await docClient.send(new GetCommand({ TableName: HIRING_ASSIGNMENTS_TABLE, Key: { assignmentId } }));
        assignment = Item; // Assign fetched item
        if (!assignment || assignment.studentEmail !== req.user.email || assignment.testId !== req.user.testId) {
             console.warn(`[SAVE DETAILS] Assignment ${assignmentId} mismatch or not found.`);
             return res.status(403).json({ message: 'Assignment mismatch or not found.' });
        }
        console.log(`[SAVE DETAILS] Assignment ${assignmentId} verified.`);

        // --- Prepare Item ---
        const resultId = `init_${assignmentId}`;
        console.log(`[SAVE DETAILS] Constructed resultId for PUT: ${resultId}`);
        const initialResultItem = {
            resultId, assignmentId, candidateEmail: req.user.email, testId: assignment.testId,
            testType: assignment.testType, fullName: details.fullName, rollNumber: details.rollNumber,
            collegeName: details.collegeName, department: details.department, profileImageUrl: details.profileImageUrl,
            status: 'Initialized', submittedAt: null, answers: null, score: null,
            marksScored: null, totalMarks: null, result: null, violationReason: null,
            createdAt: new Date().toISOString()
        };
        console.log(`[SAVE DETAILS] Prepared item for ${HIRING_TEST_RESULTS_TABLE}:`, JSON.stringify(initialResultItem));

        // --- Execute PutCommand ---
        console.log(`[SAVE DETAILS] Executing PutCommand for resultId: ${resultId}...`);
        const putResult = await docClient.send(new PutCommand({
            TableName: HIRING_TEST_RESULTS_TABLE,
            Item: initialResultItem
        }));
        console.log(`[SAVE DETAILS] PutCommand successful for ${resultId}. Metadata:`, putResult.$metadata); // *** ADDED LOG ***

        // --- Verification Get (Optional but helpful) ---
        // Immediately try to read the item back to confirm it was written
        console.log(`[SAVE DETAILS] Performing verification GetCommand for resultId: ${resultId}...`);
        const { Item: verifiedItem } = await docClient.send(new GetCommand({
             TableName: HIRING_TEST_RESULTS_TABLE,
             Key: { resultId: resultId },
             ConsistentRead: true // Use consistent read for verification
         }));

        if (verifiedItem && verifiedItem.resultId === resultId) {
             console.log(`[SAVE DETAILS] VERIFICATION SUCCESS: Item ${resultId} found immediately after PUT.`); // *** ADDED LOG ***
             res.status(200).json({ message: 'Candidate details saved successfully.' });
        } else {
             // This indicates a potential major issue if the immediate consistent read fails
             console.error(`[SAVE DETAILS] VERIFICATION FAILED: Item ${resultId} NOT FOUND immediately after successful PUT! This indicates a potential DynamoDB issue or configuration problem.`); // *** ADDED LOG ***
             res.status(500).json({ message: 'Server error: Failed to verify saved details. Please contact support.' });
        }

    } catch (error) {
         console.error(`[SAVE DETAILS] Error during save/verification process for assignment ${assignmentId}:`, error);
         // Log specific details for DynamoDB errors
         if (error.name === 'ValidationException') {
            console.error('[SAVE DETAILS] DynamoDB Validation Error:', error.message);
            res.status(500).json({ message: 'Internal server error: Invalid data format for saving details.' });
         } else if (error.name === 'ResourceNotFoundException') {
             console.error('[SAVE DETAILS] DynamoDB Resource Not Found Error:', error.message);
             res.status(500).json({ message: `Server configuration error: A required table (${HIRING_ASSIGNMENTS_TABLE} or ${HIRING_TEST_RESULTS_TABLE}) might be missing.` });
         } else if (error.$metadata?.httpStatusCode) {
             console.error(`[SAVE DETAILS] DynamoDB HTTP Error Status: ${error.$metadata.httpStatusCode}`);
             res.status(500).json({ message: `Server error saving initial details (Code: ${error.$metadata.httpStatusCode}). Please contact support.` });
         } else {
             res.status(500).json({ message: 'Unknown server error saving initial details.' });
         }
    }
});

app.post('/api/public/upload-image', async (req, res) => {
    const { imageData } = req.body;
    if (!imageData) {
        return res.status(400).json({ message: 'No image data provided.' });
    }
    try {
        // Ensure Cloudinary is configured
        if (!cloudinary.config().cloud_name) {
             console.error("Cloudinary not configured!");
             return res.status(500).json({ message: 'Image upload service not configured.' });
        }
        const result = await cloudinary.uploader.upload(imageData, {
            folder: "hiring_test_captures"
        });
        console.log("[UPLOAD IMAGE] Success. URL:", result.secure_url);
        res.json({ imageUrl: result.secure_url });
    } catch (error) {
        console.error("[UPLOAD IMAGE] Error:", error);
        res.status(500).json({ message: 'Server error uploading image.' });
    }
});

app.post('/api/public/save-code-snippet', authMiddleware, async (req, res) => {
    const assignmentIdFromToken = req.user?.assignmentId;
    const testIdFromToken = req.user?.testId;
    const emailFromToken = req.user?.email;
    const isExternal = req.user?.isExternal || false;

    const { assignmentId, testId, problemId, code, language } = req.body;

    console.log('[SAVE SNIPPET] Request received. Body:', req.body, 'User:', req.user);

    // --- Validation ---
    if (!problemId || code === undefined || code === null || !language) {
        console.warn('[SAVE SNIPPET] Validation failed: Missing problemId, code, or language.');
        return res.status(400).json({ message: 'Missing problemId, code, or language.' });
    }

    // Determine the correct IDs
    const effectiveAssignmentId = isExternal ? assignmentIdFromToken : assignmentId;
    const effectiveTestId = isExternal ? testIdFromToken : testId;
    const effectiveEmail = emailFromToken;

    if (!effectiveAssignmentId || !effectiveTestId || !effectiveEmail) {
        console.error(`[SAVE SNIPPET] Critical ID missing: effectiveAssignmentId=${effectiveAssignmentId}, effectiveTestId=${effectiveTestId}, effectiveEmail=${effectiveEmail}`);
        return res.status(400).json({ message: 'Could not determine required assignment/test/user identifiers.' });
    }
    console.log(`[SAVE SNIPPET] Effective IDs: Assignment=${effectiveAssignmentId}, Test=${effectiveTestId}, Email=${effectiveEmail}, Problem=${problemId}`);

    // --- Generate snippetId (Partition Key) ---
    const snippetId = `snip_${effectiveAssignmentId}_${problemId}`;
    const primaryKey = { snippetId: snippetId };
    console.log('[SAVE SNIPPET] Using Primary Key:', primaryKey);

    try {
        // --- Check for existing snippet ---
        console.log(`[SAVE SNIPPET] Checking for existing snippet...`);
        const { Item: existingSnippet } = await docClient.send(new GetCommand({
            TableName: HIRING_CODE_SNIPPETS_TABLE,
            Key: primaryKey
        }));

        // --- Prepare full item data ---
        const snippetData = {
            snippetId: snippetId,
            assignmentId: effectiveAssignmentId,
            problemId: problemId,
            testId: effectiveTestId,
            userEmail: effectiveEmail,
            code: code,
            language: language,
            savedAt: new Date().toISOString()
        };

        if (existingSnippet) {
            // --- Update existing snippet ---
            console.log(`[SAVE SNIPPET] Existing snippet found. Updating...`);

            // *** REVISED: Using ExpressionAttributeNames for ALL attributes ***
            await docClient.send(new UpdateCommand({
                TableName: HIRING_CODE_SNIPPETS_TABLE,
                Key: primaryKey,
                UpdateExpression: "SET #c = :c, #l = :l, #ts = :ts, #tid = :tid, #email = :email, #aid = :aid, #pid = :pid",
                ExpressionAttributeNames: {
                    "#c": "code",
                    "#l": "language",
                    "#ts": "savedAt",
                    "#tid": "testId",
                    "#email": "userEmail",
                    "#aid": "assignmentId",
                    "#pid": "problemId"
                },
                ExpressionAttributeValues: {
                    ":c": code,
                    ":l": language,
                    ":ts": snippetData.savedAt,
                    ":tid": effectiveTestId,
                    ":email": effectiveEmail,
                    ":aid": effectiveAssignmentId,
                    ":pid": problemId
                }
            }));
            // *** END REVISION ***

            console.log(`[SAVE SNIPPET] Update successful.`);
            res.status(200).json({ message: 'Code snippet updated successfully.' });

        } else {
            // --- Create new snippet ---
            console.log(`[SAVE SNIPPET] No existing snippet found. Creating new...`);
            await docClient.send(new PutCommand({
                TableName: HIRING_CODE_SNIPPETS_TABLE,
                Item: snippetData
            }));
            console.log(`[SAVE SNIPPET] Creation successful.`);
            res.status(201).json({ message: 'Code snippet saved successfully.' });
        }

    } catch (error) {
        // Log the specific error from DynamoDB or other sources
        console.error(`[SAVE SNIPPET] Error saving/updating snippet with ID ${snippetId} (Assignment ${effectiveAssignmentId}, Problem ${problemId}):`, error);

        let errorMessage = 'Server error saving code snippet.'; // Default message
        if (error.name === 'ValidationException') {
            console.error('[SAVE SNIPPET] DynamoDB Validation Error:', error.message);
            // Provide a slightly more specific message if possible, but avoid exposing too much detail
            errorMessage = 'Data validation failed during save.';
        } else if (error.name === 'ResourceNotFoundException') {
            console.error(`[SAVE SNIPPET] DynamoDB Resource Not Found Error: Table ${HIRING_CODE_SNIPPETS_TABLE} might be missing.`);
            errorMessage = 'Server configuration error (table not found).';
        } else if (error.$metadata?.httpStatusCode) {
             console.error(`[SAVE SNIPPET] DynamoDB HTTP Error Status: ${error.$metadata.httpStatusCode}`);
             errorMessage = `Server error communicating with database (Code: ${error.$metadata.httpStatusCode}).`;
        }

        // Send the potentially more specific error message back
        res.status(500).json({ message: errorMessage });
    }
});

app.get('/api/hiring/job-applicant-pools/:jobId', hiringModeratorAuth, async (req, res) => {
    const { jobId } = req.params;

    try {
        // --- 1. Get Job details to verify ownership and get total applicant count ---
        const { Item: job } = await docClient.send(new GetCommand({
            TableName: HIRING_JOBS_TABLE, Key: { jobId }
        }));
        if (!job || job.createdBy !== req.user.email) {
            return res.status(403).json({ message: 'Access denied or job not found.' });
        }

        // --- 2. Get count of "All Applicants" ---
        // We scan HIRING_APPLICATIONS_TABLE (where students first apply)
        const { Items: allApplications } = await docClient.send(new QueryCommand({
            TableName: HIRING_APPLICATIONS_TABLE,
            IndexName: "jobId-index", // Assumes GSI with HASH = jobId
            KeyConditionExpression: "jobId = :jid",
            ExpressionAttributeValues: { ":jid": jobId }
        }));
        const allApplicantCount = allApplications.length;

        // This is the first, default pool
        let pools = [
            { 
                filterKey: "all", 
                displayText: `All Applicants for "${job.title}" (${allApplicantCount})` 
            }
        ];

        // --- 3. Find all test results associated with this job ---
        const { Items: results } = await docClient.send(new ScanCommand({
            TableName: HIRING_TEST_RESULTS_TABLE,
            FilterExpression: "jobId = :jid",
            ExpressionAttributeValues: { ":jid": jobId }
        }));

        if (!results || results.length === 0) {
            // No test results yet, just return the "All Applicants" pool
            return res.json(pools);
        }

        // --- 4. Group results by testId to find unique tests taken ---
        const resultsByTest = results.reduce((acc, res) => {
            if (!res.testId) return acc;
            if (!acc[res.testId]) {
                acc[res.testId] = { passed: 0, failed: 0, testType: res.testType, testTitle: res.testTitle };
            }
            if (res.result === "Pass") {
                acc[res.testId].passed++;
            } else {
                acc[res.testId].failed++;
            }
            return acc;
        }, {});

        // --- 5. Create filterable pools from the grouped results ---
        for (const [testId, data] of Object.entries(resultsByTest)) {
            const testTitle = data.testTitle || `${data.testType} Test (ID: ...${testId.slice(-4)})`;
            
            if(data.passed > 0) {
                pools.push({
                    filterKey: `passed:${testId}`,
                    displayText: `Passed: "${testTitle}" (${data.passed})`
                });
            }
            if(data.failed > 0) {
                pools.push({
                    filterKey: `failed:${testId}`,
                    displayText: `Failed: "${testTitle}" (${data.failed})`
                });
            }
        }

        res.json(pools);

    } catch (error) {
        console.error(`[JOB APPLICANT POOLS] Error for jobId ${jobId}:`, error);
        res.status(500).json({ message: 'Server error fetching applicant pools.' });
    }
});


// ---
// 5. NEW ENDPOINT: GET /api/hiring/job-applicants
// ---
// Add this new endpoint to your backend.js file.

app.get('/api/hiring/job-applicants', hiringModeratorAuth, async (req, res) => {
    const { jobId, filterKey } = req.query;

    if (!jobId || !filterKey) {
        return res.status(400).json({ message: 'jobId and filterKey are required.' });
    }

    try {
        let emails = [];

        if (filterKey === 'all') {
            // --- Fetch ALL applicants from the applications table ---
            const { Items } = await docClient.send(new QueryCommand({
                TableName: HIRING_APPLICATIONS_TABLE,
                IndexName: "jobId-index", // Assumes GSI with HASH = jobId
                KeyConditionExpression: "jobId = :jid",
                ExpressionAttributeValues: { ":jid": jobId },
                ProjectionExpression: "email" // Only fetch the email
            }));
            emails = Items.map(app => app.email);

        } else {
            // --- Fetch from results table based on filter ---
            const [status, testId] = filterKey.split(':');
            
            if (!status || !testId || (status !== 'passed' && status !== 'failed')) {
                return res.status(400).json({ message: 'Invalid filterKey format. Expected "all", "passed:testid", or "failed:testid".' });
            }

            const resultString = status === 'passed' ? 'Pass' : 'Fail';

            const { Items } = await docClient.send(new ScanCommand({
                TableName: HIRING_TEST_RESULTS_TABLE,
                FilterExpression: "jobId = :jid AND testId = :tid AND #res = :result",
                ExpressionAttributeNames: { "#res": "result" },
                ExpressionAttributeValues: {
                    ":jid": jobId,
                    ":tid": testId,
                    ":result": resultString
                },
                ProjectionExpression: "candidateEmail" // Only fetch the email
            }));
            
            emails = Items.map(res => res.candidateEmail);
        }

        // Return unique emails
        res.json([...new Set(emails)]);

    } catch (error) {
        console.error(`[JOB APPLICANTS] Error for jobId ${jobId}, filter ${filterKey}:`, error);
        res.status(500).json({ message: 'Server error fetching applicants.' });
    }
});
// Add this to your backend.js file
app.delete('/api/hiring/applications/:applicationId', hiringModeratorAuth, async (req, res) => {
    const { applicationId } = req.params;
    
    // You should add a check here to ensure the moderator (req.user.email)
    // is authorized to delete this application, e.g., by checking
    // who created the job associated with the application.

    try {
        await docClient.send(new DeleteCommand({
            TableName: HIRING_APPLICATIONS_TABLE,
            Key: { applicationId: applicationId }
        }));
        res.status(200).json({ message: 'Application deleted successfully.' });
    } catch (error) {
        console.error("Delete Application Error:", error);
        res.status(500).json({ message: 'Server error deleting application.' });
    }
});

app.get('/api/student/my-tests', studentAuthMiddleware, async (req, res) => {
    const studentEmail = req.user.email;
    if (!studentEmail) {
        return res.status(401).json({ message: 'Authentication required.' });
    }

    console.log(`[MY_TESTS_START] Fetching tests for student ${studentEmail}`);
    let combinedItems = [];
    const aptitudeTestIdsToFetch = [];
    const codingTestIdsToFetch = [];

    try {
        // --- 1. Fetch Test Assignments ---
        console.log(`[MY_TESTS_FETCH] Fetching from ${HIRING_ASSIGNMENTS_TABLE}`);
        const { Items: assignments } = await docClient.send(new ScanCommand({
            TableName: HIRING_ASSIGNMENTS_TABLE, // [cite: backend.js]
            FilterExpression: "studentEmail = :emailVal",
            ExpressionAttributeValues: { ":emailVal": studentEmail }
        }));

        if (!assignments || assignments.length === 0) {
            console.log(`[MY_TESTS_FETCH] No test assignments found.`);
            return res.json([]);
        }

        console.log(`[MY_TESTS_FETCH] Found ${assignments.length} test assignments.`);
        const baseUrl = req.protocol + '://' + req.get('host');
        const pageName = 'download-test-app.html'; // [cite: backend.js]

        assignments.forEach(assign => {
            const testLink = `${baseUrl}/${pageName}?token=${assign.testToken}`;
            combinedItems.push({
                type: 'test',
                id: assign.assignmentId,
                testId: assign.testId,
                testType: assign.testType,
                startTime: assign.startTime,
                endTime: assign.endTime,
                testLink: testLink,
                date: assign.assignedAt
            });
            
            if (assign.testType === 'aptitude') {
                aptitudeTestIdsToFetch.push(assign.testId);
            } else if (assign.testType === 'coding') {
                codingTestIdsToFetch.push(assign.testId);
            }
        });

        // --- 2. Batch Fetch All Test Details (with de-duplication) ---
        let aptitudeTestMap = new Map();
        let codingTestMap = new Map();

        if (aptitudeTestIdsToFetch.length > 0) {
            const uniqueAptitudeTestKeys = [...new Set(aptitudeTestIdsToFetch)].map(id => ({ aptitudeTestId: id }));
            const { Responses } = await docClient.send(new BatchGetCommand({
                RequestItems: { [HIRING_APTITUDE_TESTS_TABLE]: { Keys: uniqueAptitudeTestKeys } }
            }));
            (Responses[HIRING_APTITUDE_TESTS_TABLE] || []).forEach(t => aptitudeTestMap.set(t.aptitudeTestId, t));
            console.log(`[MY_TESTS_BATCH] Fetched ${aptitudeTestMap.size} aptitude test details.`);
        }
        if (codingTestIdsToFetch.length > 0) {
            const uniqueCodingTestKeys = [...new Set(codingTestIdsToFetch)].map(id => ({ codingTestId: id }));
            const { Responses } = await docClient.send(new BatchGetCommand({
                RequestItems: { [HIRING_CODING_TESTS_TABLE]: { Keys: uniqueCodingTestKeys } }
            }));
            (Responses[HIRING_CODING_TESTS_TABLE] || []).forEach(t => codingTestMap.set(t.codingTestId, t));
            console.log(`[MY_TESTS_BATCH] Fetched ${codingTestMap.size} coding test details.`);
        }

        // --- 3. Enrich Combined List ---
        const enrichedItems = combinedItems.map(item => {
            let test;
            if (item.testType === 'aptitude') {
                test = aptitudeTestMap.get(item.testId);
            } else if (item.testType === 'coding') {
                test = codingTestMap.get(item.testId);
            }
            return {
                ...item,
                testTitle: test?.title || 'Test Title Unavailable',
            };
        });

        // Sort by date, newest first
        enrichedItems.sort((a, b) => new Date(b.date) - new Date(a.date));

        console.log(`[MY_TESTS_SUCCESS] Returning ${enrichedItems.length} combined items for student ${studentEmail}`);
        res.json(enrichedItems);

    } catch (error) {
        console.error(`[MY_TESTS_FATAL_ERROR] Failed fetching items for student ${studentEmail}:`, error);
        res.status(500).json({ message: 'Server error fetching your tests.' });
    }
});
// NEW: Get a single aptitude test's details (for editing)
app.get('/api/hiring/aptitude-tests/:aptitudeTestId', hiringModeratorAuth, async (req, res) => {
    const { aptitudeTestId } = req.params;
    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: HIRING_APTITUDE_TESTS_TABLE,
            Key: { aptitudeTestId }
        }));

        if (!Item || Item.createdBy !== req.user.email) {
            return res.status(404).json({ message: 'Aptitude test not found or access denied.' });
        }
        res.json(Item);
    } catch (error) {
        console.error("Get Single Aptitude Test Error:", error);
        res.status(500).json({ message: 'Server error fetching aptitude test.' });
    }
});

// NEW: Update an existing aptitude test
app.put('/api/hiring/aptitude-tests/:aptitudeTestId', hiringModeratorAuth, async (req, res) => {
    const { aptitudeTestId } = req.params;
    // NEW: Destructure useSectionSettings and check new section fields
    const { testTitle, duration, totalMarks, passingPercentage, sections, useSectionSettings } = req.body;

    if (!testTitle || !duration || !totalMarks || !passingPercentage || !sections) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    // Validate section-specific settings if enabled
    if (useSectionSettings) {
        if (!sections || sections.some(s => !s.sectionTimer || s.sectionQualifyingMarks === undefined || s.sectionQualifyingMarks === null)) {
            return res.status(400).json({ message: 'When section-specific settings are enabled, every section must have a timer and qualifying marks (can be 0).' });
        }
    }

    try {
        const { Item: existingTest } = await docClient.send(new GetCommand({
            TableName: HIRING_APTITUDE_TESTS_TABLE,
            Key: { aptitudeTestId }
        }));
        if (!existingTest || existingTest.createdBy !== req.user.email) {
            return res.status(403).json({ message: 'Access denied.' });
        }

        const updatedTest = {
            ...existingTest,
            title: testTitle,
            duration: parseInt(duration, 10),
            totalMarks: parseInt(totalMarks, 10),
            passingPercentage: parseInt(passingPercentage, 10),
            sections, // This now contains { title, questions, sectionTimer, sectionQualifyingMarks }
            useSectionSettings: useSectionSettings || false, // NEW: Save this flag
            updatedAt: new Date().toISOString()
        };

        await docClient.send(new PutCommand({
            TableName: HIRING_APTITUDE_TESTS_TABLE,
            Item: updatedTest
        }));
        
        res.status(200).json({ message: 'Aptitude test updated successfully!', test: updatedTest });
    } catch (error) {
        console.error("Update Aptitude Test Error:", error);
        res.status(500).json({ message: 'Server error updating aptitude test.' });
    }
});

// NEW: Delete an aptitude test
app.delete('/api/hiring/aptitude-tests/:aptitudeTestId', hiringModeratorAuth, async (req, res) => {
    const { aptitudeTestId } = req.params;
    try {
        // Check ownership
        const { Item } = await docClient.send(new GetCommand({
            TableName: HIRING_APTITUDE_TESTS_TABLE,
            Key: { aptitudeTestId }
        }));
        if (!Item || Item.createdBy !== req.user.email) {
            return res.status(403).json({ message: 'Access denied.' });
        }

        await docClient.send(new DeleteCommand({
            TableName: HIRING_APTITUDE_TESTS_TABLE,
            Key: { aptitudeTestId }
        }));
        
        // You might also want to delete related assignments from HIRING_ASSIGNMENTS_TABLE
        
        res.status(200).json({ message: 'Aptitude test deleted successfully.' });
    } catch (error) {
        console.error("Delete Aptitude Test Error:", error);
        res.status(500).json({ message: 'Server error deleting aptitude test.' });
    }
});




// NEW: Delete a coding problem
app.delete('/api/hiring/coding-problems/:problemId', hiringModeratorAuth, async (req, res) => {
    const { problemId } = req.params;
    try {
        // Check ownership
        const { Item } = await docClient.send(new GetCommand({
            TableName: HIRING_CODING_PROBLEMS_TABLE,
            Key: { problemId }
        }));
        if (!Item || Item.createdBy !== req.user.email) {
            return res.status(403).json({ message: 'Access denied.' });
        }

        await docClient.send(new DeleteCommand({
            TableName: HIRING_CODING_PROBLEMS_TABLE,
            Key: { problemId }
        }));
        
        // Note: You should also check if this problem is used in any HIRING_CODING_TESTS_TABLE
        // and handle that (e.g., prevent deletion or remove from tests).
        
        res.status(200).json({ message: 'Coding problem deleted successfully.' });
    } catch (error) {
        console.error("Delete Coding Problem Error:", error);
        res.status(500).json({ message: 'Server error deleting problem.' });
    }
});



// NEW: Get a single coding test's details (for editing)
app.get('/api/hiring/coding-tests/:codingTestId', hiringModeratorAuth, async (req, res) => {
    const { codingTestId } = req.params;
    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: HIRING_CODING_TESTS_TABLE,
            Key: { codingTestId }
        }));

        if (!Item || Item.createdBy !== req.user.email) {
            return res.status(404).json({ message: 'Coding test not found or access denied.' });
        }
        res.json(Item);
    } catch (error) {
        console.error("Get Single Coding Test Error:", error);
        res.status(500).json({ message: 'Server error fetching coding test.' });
    }
});

// NEW: Update an existing coding test
app.put('/api/hiring/coding-tests/:codingTestId', hiringModeratorAuth, async (req, res) => {
    const { codingTestId } = req.params;
    // NEW: Destructure useSectionSettings and passingPercentage
    const { testTitle, duration, sections, useSectionSettings, passingPercentage } = req.body;

    if (!testTitle || !sections || !Array.isArray(sections) || sections.length === 0) {
        return res.status(400).json({ message: 'Missing required fields.' });
    }
    
    let totalMarks = 0;
    try {
        const sectionsToStore = sections.map(section => {
            if (!section.title || !section.problems || !Array.isArray(section.problems)) {
                throw new Error('Invalid section format.');
            }
            
            // NEW: Validate section-specific settings if enabled
            if (useSectionSettings) {
                if (!section.sectionTimer || section.sectionTimer <= 0) {
                    throw new Error(`Please provide a valid timer for section: "${section.title}"`);
                }
                if (section.sectionQualifyingMarks === null || section.sectionQualifyingMarks === undefined || section.sectionQualifyingMarks < 0) {
                    throw new Error(`Please provide valid qualifying marks (can be 0) for section: "${section.title}"`);
                }
            }
            
            const problemsToStore = section.problems.map(p => {
                const score = parseInt(p.score, 10) || 0;
                totalMarks += score;
                return {
                    problemId: p.id || p.problemId,
                    title: p.title,
                    difficulty: p.difficulty,
                    score: score
                };
            });
            return { 
                title: section.title, 
                problems: problemsToStore,
                sectionTimer: section.sectionTimer || null, // NEW: Save this
                sectionQualifyingMarks: section.sectionQualifyingMarks || 0 // NEW: Save this
            };
        });

        const { Item: existingTest } = await docClient.send(new GetCommand({
            TableName: HIRING_CODING_TESTS_TABLE,
            Key: { codingTestId }
        }));
        if (!existingTest || existingTest.createdBy !== req.user.email) {
            return res.status(403).json({ message: 'Access denied.' });
        }

        const updatedTest = {
            ...existingTest,
            title: testTitle,
            duration: parseInt(duration, 10) || 0,
            passingPercentage: parseInt(passingPercentage, 10) || null, // NEW: Save this
            totalMarks,
            sections: sectionsToStore,
            useSectionSettings: useSectionSettings || false, // NEW: Save this flag
            updatedAt: new Date().toISOString()
        };

        await docClient.send(new PutCommand({
            TableName: HIRING_CODING_TESTS_TABLE,
            Item: updatedTest
        }));
        
        res.status(200).json({ message: 'Coding test updated successfully!', test: updatedTest });
    } catch (error) {
        console.error("Update Coding Test Error:", error);
        if (error.message.includes('Invalid section format') || error.message.includes('Please provide')) {
            return res.status(400).json({ message: error.message });
        }
        res.status(500).json({ message: 'Server error updating coding test.' });
    }
});
// NEW: Delete a coding test
app.delete('/api/hiring/coding-tests/:codingTestId', hiringModeratorAuth, async (req, res) => {
    const { codingTestId } = req.params;
    try {
        // Check ownership
        const { Item } = await docClient.send(new GetCommand({
            TableName: HIRING_CODING_TESTS_TABLE,
            Key: { codingTestId }
        }));
        if (!Item || Item.createdBy !== req.user.email) {
            return res.status(403).json({ message: 'Access denied.' });
        }

        await docClient.send(new DeleteCommand({
            TableName: HIRING_CODING_TESTS_TABLE,
            Key: { codingTestId }
        }));
        
        // You might also want to delete related assignments from HIRING_ASSIGNMENTS_TABLE
        
        res.status(200).json({ message: 'Coding test deleted successfully.' });
    } catch (error) {
        console.error("Delete Coding Test Error:", error);
        res.status(500).json({ message: 'Server error deleting coding test.' });
    }
});

app.post('/api/hiring/upload-media', hiringModeratorAuth, upload.single('mediaFile'), async (req, res) => {
    if (!req.file) {
        console.log("[UPLOAD MEDIA] No file received.");
        return res.status(400).json({ message: 'No media file was uploaded.' });
    }

    console.log(`[UPLOAD MEDIA] Received file: ${req.file.originalname}, Size: ${req.file.size}, Type: ${req.file.mimetype}`);

    // Create a unique file key for S3
    const fileExtension = req.file.originalname.split('.').pop();
    const fileKey = `test-media/${uuidv4()}.${fileExtension}`;

    const s3Params = {
        Bucket: S3_BUCKET_NAME,
        Key: fileKey,
        Body: req.file.buffer,
        ContentType: req.file.mimetype
    };

    try {
        console.log(`[UPLOAD MEDIA] Uploading '${fileKey}' to S3 bucket '${S3_BUCKET_NAME}'...`);
        await s3Client.send(new PutObjectCommand(s3Params));

        // Construct the public URL
        const s3Url = `https://${S3_BUCKET_NAME}.s3.${AWS_S3_REGION}.amazonaws.com/${fileKey}`;
        
        console.log(`[UPLOAD MEDIA] Upload successful. URL: ${s3Url}`);
        res.json({ url: s3Url });

    } catch (error) {
        console.error("[UPLOAD MEDIA] Error uploading to S3:", error);
        res.status(500).json({ message: 'Server error during file upload.' });
    }
});

// =================================================================
// --- ADMIN & HIRING MODERATOR: INTERVIEWER MANAGEMENT ---
// =================================================================

/**
 * @route   POST /api/admin/interviewers
 * @desc    Admin OR Moderator: Create a new Interviewer account
 * @access  Private (Admin, Hiring Moderator)
 */
app.post('/api/admin/interviewers', authMiddleware, async (req, res) => {
    // UPDATED: Allow both Admin and Hiring Moderator
    if (req.user.role !== 'Admin' && req.user.role !== 'Hiring Moderator') {
        return res.status(403).json({ message: 'Access denied. Admin or Hiring Moderator role required.' });
    }
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) {
        return res.status(400).json({ message: 'Please provide full name, email, and password.' });
    }
    try {
        const existingUser = await docClient.send(new GetCommand({ TableName: "TestifyUsers", Key: { email: email.toLowerCase() } }));
        if (existingUser.Item) {
            return res.status(400).json({ message: 'User with this email already exists.' });
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newInterviewer = {
            email: email.toLowerCase(),
            fullName,
            password: hashedPassword,
            role: "Interviewer", // This creates an "Interviewer" role
            isBlocked: false,
            company: "HireWithUs" 
        };
        await docClient.send(new PutCommand({ TableName: "TestifyUsers", Item: newInterviewer }));
        res.status(201).json({ message: 'Interviewer account created successfully!' });
    } catch (error) {
        console.error("Create Interviewer Error:", error);
        res.status(500).json({ message: 'Server error during interviewer creation.' });
    }
});

/**
 * @route   GET /api/admin/interviewers
 * @desc    Admin OR Moderator: Get all Interviewer accounts
 * @access  Private (Admin, Hiring Moderator)
 */
app.get('/api/admin/interviewers', authMiddleware, async (req, res) => {
    // UPDATED: Allow both Admin and Hiring Moderator
    if (req.user.role !== 'Admin' && req.user.role !== 'Hiring Moderator') {
        return res.status(403).json({ message: 'Access denied. Admin or Hiring Moderator role required.' });
    }
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyUsers",
            FilterExpression: "#role = :role",
            ExpressionAttributeNames: { "#role": "role" },
            ExpressionAttributeValues: { ":role": "Interviewer" }
        }));
        res.json(Items.map(({ password, ...rest }) => rest)); // Exclude password
    } catch (error) {
        console.error("Get Interviewers Error:", error);
        res.status(500).json({ message: 'Server error fetching interviewers.' });
    }
});

/**
 * @route   DELETE /api/admin/interviewers/:email
 * @desc    Admin OR Moderator: Delete an Interviewer account
 * @access  Private (Admin, Hiring Moderator)
 */
app.delete('/api/admin/interviewers/:email', authMiddleware, async (req, res) => {
    // UPDATED: Allow both Admin and Hiring Moderator
    if (req.user.role !== 'Admin' && req.user.role !== 'Hiring Moderator') {
        return res.status(403).json({ message: 'Access denied. Admin or Hiring Moderator role required.' });
    }
    const { email } = req.params;
    try {
        // You might want to add a check here to ensure a moderator can't delete an admin
        const { Item } = await docClient.send(new GetCommand({ TableName: "TestifyUsers", Key: { email } }));
        if (Item && Item.role === 'Admin' && req.user.role !== 'Admin') {
             return res.status(403).json({ message: 'Hiring Moderators cannot delete Admin accounts.' });
        }

        await docClient.send(new DeleteCommand({
            TableName: "TestifyUsers",
            Key: { email }
        }));
        res.json({ message: 'Interviewer deleted successfully.' });
    } catch (error) {
        console.error("Delete Interviewer Error:", error);
        res.status(500).json({ message: 'Server error deleting interviewer.' });
    }
});


// =================================================================
// --- HIRING MODERATOR: INTERVIEW SCHEDULING ENDPOINTS ---
// =================================================================

/**
 * @route   GET /api/hiring/interviewers
 * @desc    Moderator: Get list of available interviewers for scheduling
 * @access  Private (Hiring Moderator)
 */
app.get('/api/hiring/interviewers', hiringModeratorAuth, async (req, res) => {
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyUsers",
            FilterExpression: "#role = :role",
            ExpressionAttributeNames: { "#role": "role" },
            ExpressionAttributeValues: { ":role": "Interviewer" }
        }));
        // Send only name and email
        res.json(Items.map(item => ({ email: item.email, fullName: item.fullName })));
    } catch (error) {
        console.error("Get Interviewers for Scheduling Error:", error);
        res.status(500).json({ message: 'Server error fetching interviewers.' });
    }
});

/**
 * @route   POST /api/hiring/schedule-interview
 * @desc    Moderator: Confirms and saves an auto-generated schedule
 * @access  Private (Hiring Moderator)
 */
app.post('/api/hiring/schedule-interview', hiringModeratorAuth, async (req, res) => {
    const { eventName, schedule, jobId, jobTitle } = req.body;
    const moderatorEmail = req.user.email;

    if (!eventName || !schedule || !Array.isArray(schedule) || schedule.length === 0 || !jobId) {
        return res.status(400).json({ message: 'Event name, jobId, jobTitle and a schedule array are required.' });
    }

    const eventId = `EVENT_${uuidv4()}`;
    const writeRequests = [];
    const interviewerSchedules = {}; // To batch emails to interviewers
    let studentJoinTokens = {}; // To store tokens for student emails

    try {
        // --- 1. Create the Parent "Event" Item ---
        const eventItem = {
            PK: eventId,
            SK: "METADATA",
            GSI1_PK: `REPORT#${eventId}`, // GSI for moderator to query all reports
            GSI1_SK: `METADATA#${new Date().toISOString()}`,
            eventId,
            eventName,
            jobId,
            jobTitle,
            createdBy: moderatorEmail,
            createdAt: new Date().toISOString(),
            status: "CONFIRMED"
        };
        writeRequests.push({ PutRequest: { Item: eventItem } });

        // --- 2. Create all "Slot" Items ---
        for (const item of schedule) {
            const slotId = `SLOT_${uuidv4()}`;
            const { candidateEmail, candidateName, interviewerEmail, interviewerName, startTime, endTime } = item;
            
            // Generate a unique token for this student+slot
            const slotTokenPayload = {
                user: {
                    email: candidateEmail,
                    slotId: slotId,
                    interviewerEmail: interviewerEmail,
                    isExternal: true // Use the same external flag as the test app
                }
            };
            // This token allows the student to join the room
            const studentJoinToken = jwt.sign(slotTokenPayload, JWT_SECRET, { expiresIn: '7d' });
            studentJoinTokens[candidateEmail] = studentJoinToken; // Store token for email

            const slotItem = {
                PK: eventId, // Links slot to the event
                SK: `SLOT#${startTime}#${interviewerEmail}`, // Sorts by time and interviewer
                GSI1_PK: interviewerEmail, // GSI for interviewer to fetch their schedule
                GSI1_SK: startTime, // Sorts schedule by time
                GSI2_PK: slotId, // GSI to find a slot by its simple ID
                GSI2_SK: slotId,
                slotId,
                eventId,
                jobId,
                candidateEmail,
                candidateName,
                interviewerEmail,
                interviewerName,
                startTime,
                endTime,
                studentJoinToken,
                interviewStatus: "UPCOMING", // e.g., UPCOMING, ACTIVE, COMPLETED
                studentDetailsSubmitted: false, // NEW FIELD
                chatHistory: [], // NEW FIELD
                assignedProblems: [], // NEW FIELD
                latestCode: "", // NEW FIELD
                latestLanguage: "javascript" // NEW FIELD
            };
            writeRequests.push({ PutRequest: { Item: slotItem } });

            // Batch emails
            if (!interviewerSchedules[interviewerEmail]) {
                interviewerSchedules[interviewerEmail] = { name: interviewerName, slots: [] };
            }
            interviewerSchedules[interviewerEmail].slots.push(item);
        }

        // --- 3. Save to DynamoDB in Batches ---
        const batches = [];
        for (let i = 0; i < writeRequests.length; i += 25) {
            batches.push(writeRequests.slice(i, i + 25));
        }
        for (const batch of batches) {
            await docClient.send(new BatchWriteCommand({
                RequestItems: { [HIRING_INTERVIEWS_TABLE]: batch }
            }));
        }
        
        // --- 4. Send Emails (Not waiting for this to finish) ---
        (async () => {
            const baseUrl = req.protocol + '://' + req.get('host');

            // Send to Students
            for (const item of schedule) {
                
                // --- THIS IS THE UPDATED PATH ---
                const joinLink = `${baseUrl}/student-interview-room.html?token=${studentJoinTokens[item.candidateEmail]}`;
                // --- END OF UPDATE ---

                await sendEmailWithSES({
                    to: item.candidateEmail,
                    subject: `Interview Scheduled: ${eventName}`,
                    html: `
                        <!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Interview Schedule</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body {
      font-family: 'Inter', 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }
  </style>
</head>
<body class="bg-gradient-to-br from-gray-100 to-gray-200 text-gray-800">
  <div class="max-w-2xl mx-auto my-10 bg-white rounded-2xl shadow-2xl overflow-hidden border border-gray-200">

    <!-- Header -->
    <div class="bg-gradient-to-br from-blue-600 to-blue-700 text-white text-center p-10">
      <h1 class="text-3xl sm:text-4xl font-extrabold tracking-tight mb-2">
        ${eventName} - Interview Invitation
      </h1>
      <p class="text-blue-100 text-sm sm:text-base font-medium">
        Organized by <span class="font-semibold text-white">HireWithUS</span>
      </p>
    </div>

    <!-- Body -->
    <div class="p-8 sm:p-10 leading-relaxed text-gray-700">
      <p class="text-lg mb-5">
        Hello <strong class="text-gray-900">${item.candidateName}</strong>,
      </p>

      <p class="mb-6">
        You are scheduled for an interview for the position:
        <strong class="text-blue-700">${jobTitle}</strong>.
      </p>

      <!-- Interview Details -->
      <div class="bg-gradient-to-br from-blue-50 to-blue-100 border border-blue-200 rounded-xl shadow-sm p-6 mb-8">
        <h2 class="text-xl font-semibold text-blue-800 mb-4 flex items-center">
          <i class="fas fa-calendar-check mr-2 text-blue-700"></i> Interview Details
        </h2>
        <ul class="space-y-3 text-gray-800">
          <li><strong>Interviewer:</strong> ${item.interviewerName}</li>
          <li><strong>Time:</strong> ${new Date(item.startTime).toLocaleString()} (IST)</li>
          <li>
            <strong>Join Link:</strong>
            <a href="${joinLink}" class="text-blue-600 font-medium underline hover:text-blue-800">Click here to join</a>
          </li>
        </ul>
      </div>

      <!-- Instructions -->
      <div class="bg-yellow-50 border-l-4 border-yellow-400 p-6 rounded-md shadow-sm mb-8">
        <h2 class="text-lg font-semibold text-yellow-800 mb-3 flex items-center">
          <i class="fas fa-exclamation-circle mr-2 text-yellow-600"></i>
          Important Instructions
        </h2>
        <ul class="list-disc pl-5 space-y-2 text-yellow-900 text-sm sm:text-base">
          <li>Attend the interview in <strong>formal attire</strong>.</li>
          <li>Ensure you are in a <strong>quiet environment</strong> with no background noise.</li>
          <li>Use a <strong>laptop or PC</strong> with a functional camera and microphone.</li>
          <li>Maintain a <strong>stable internet connection</strong>.</li>
          <li>Join <strong>10 minutes before the scheduled time</strong> for verification.</li>
          <li>Keep your ID card and resume ready for quick reference.</li>
          <li><strong>Do not switch tabs</strong> or minimize the screen during the interview.</li>
          <li>For support mail us <strong>support@xetasolutions.in</strong> or <strong>support@testify-lac.com</strong></li>
        </ul>
      </div>

      <!-- CTA -->
      <div class="text-center">
        <a href="${joinLink}"
           class="inline-block bg-blue-600 text-white font-semibold px-8 py-3 rounded-lg shadow-md hover:bg-blue-700 hover:shadow-lg transform hover:scale-105 transition-all duration-300">
          Join Interview
        </a>
      </div>
    </div>

    <!-- Footer -->
    <div class="bg-gray-50 text-center p-6 border-t border-gray-200 text-sm text-gray-600">
      <p class="mb-3">
        Best Regards,<br />
        <strong class="font-semibold text-gray-800">The HireWithUS Team</strong>
      </p>
      <div class="flex justify-center items-center gap-3 mt-3">
        <span class="text-xs text-gray-500">
          A product of <a href="https://www.xetasolutions.in" class="underline text-blue-600 hover:text-blue-800">Xeta Solutions</a>
        </span>
        <img
          src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1760704788/XETA_SOLUTIONS_bt6bgn.jpg"
          alt="Xeta Solutions Logo"
          class="h-6 w-auto rounded-md border border-gray-300 shadow-sm"
        />
      </div>
      <p class="mt-4 text-xs text-gray-500">
        This is an automated email — please do not reply.
      </p>
    </div>
  </div>

  <!-- FontAwesome for icons -->
  <script src="https://kit.fontawesome.com/a2e0e6b63c.js" crossorigin="anonymous"></script>
</body>
</html>

                    `
                });
            }

            // Send to Interviewers
            for (const [email, data] of Object.entries(interviewerSchedules)) {
                const scheduleHtml = data.slots
                    .sort((a, b) => new Date(a.startTime) - new Date(b.startTime))
                    .map(slot => `<li>${new Date(slot.startTime).toLocaleTimeString()}: ${slot.candidateName}</li>`)
                    .join('');
                
                await sendEmailWithSES({
                    to: email,
                    subject: `Your Interview Schedule: ${eventName}`,
                    html: `
                        <!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Interview Schedule</title>
  <!-- Load Tailwind CSS via CDN -->
  <script src="https://cdn.tailwindcss.com"></script>
  <!-- 
    Note: For production emails, it's best to inline these CSS classes 
    using a tool like Maizzle or Tailwind's CLI, as many email 
    clients don't support <script> tags.
  -->
  <style>
    /* Fallback font for email clients that don't load Tailwind's default */
    body {
      font-family: 'Inter', 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }
  </style>
</head>
<body class="bg-gray-100 text-gray-800">
  <div class="max-w-2xl mx-auto my-8 sm:my-10 bg-white rounded-xl shadow-lg overflow-hidden">
    
    <!-- Header -->
    <div class="bg-gradient-to-br from-blue-600 to-blue-700 text-white p-8 text-center">
      <h1 class="text-3xl font-bold tracking-wide m-0">
        ${eventName} - Interview Schedule
      </h1>
    </div>

    <!-- Content -->
    <div class="p-6 sm:p-10 leading-relaxed text-gray-700">
      <p class="mb-4">Hello <strong class="font-semibold text-gray-900">${data.name}</strong>,</p>
      <p class="mb-6">
        We’re excited to share your schedule for the
        <strong class="font-semibold text-gray-900">${eventName}</strong> interview event. Please
        review your interview details below:
      </p>

      <!-- Schedule Block -->
      <div class="bg-gray-50 border border-gray-200 rounded-lg p-6 my-6">
        <ul class="divide-y divide-gray-200">
          <!-- 
            Your ${scheduleHtml} variable should inject <li> elements here.
            For best results, format them like:
            <li class="py-3">
              <strong class="text-gray-900">10:00 AM - 10:45 AM:</strong>
              <span class="text-gray-700">Technical Interview with John Smith</span>
            </li>
            <li class="py-3">
              <strong class="text-gray-900">11:00 AM - 11:30 AM:</strong>
              <span class="text-gray-700">HR Interview with Jane Doe</span>
            </li>
          -->
          ${scheduleHtml}
        </ul>
      </div>

      <!-- Instructions Block -->
      <div class="bg-yellow-50 border-l-4 border-yellow-400 p-6 rounded-md mt-8">
        <h2 class="text-lg font-semibold text-yellow-800 mb-3">
          Important Instructions
        </h2>
        <ul class="list-disc pl-5 space-y-2 text-yellow-900">
          <li>Attend the interview in <strong>formal attire</strong>.</li>
          <li>Ensure you are in a <strong>quiet room</strong> with no background noise.</li>
          <li>Use a <strong>laptop or PC</strong> with a good camera, speaker, and microphone.</li>
          <li>Make sure you have a <strong>stable internet connection</strong>.</li>
          <li>
            <strong>Login and complete verification at least 10 minutes before</strong>
            your scheduled interview time.
          </li>
          <li>
            Interview timings may
            <strong>slightly vary based on interviewer availability</strong>.
          </li>
          <li>
            <strong>Do not switch tabs</strong> or minimize the screen during the
            interview.
          </li>
          <li>
            <strong>Do not end screen sharing</strong> once started — doing so will
            <strong>auto-submit</strong> your session.
          </li>
        </ul>
      </div>

      <!-- Button -->
      <p class="text-center mt-8">
        <a
          href="${baseUrl}/interviewer-portal.html"
          class="inline-block bg-blue-600 text-white no-underline py-3 px-8 rounded-md font-semibold transition-colors duration-200 hover:bg-blue-700"
        >
          Go to Dashboard
        </a>
      </p>
    </div>

    <!-- Footer -->
    <div class="bg-gray-50 text-center p-6 border-t border-gray-200 text-sm text-gray-600">
      <p class="mb-4">Best Regards,<br /><strong class="font-semibold text-gray-700">The HireWithUS Team</strong></p>
      
      <div class="flex justify-center items-center gap-3 mt-4">
        <span class="text-xs">A product of</span>
        <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1760704788/XETA_SOLUTIONS_bt6bgn.jpg" alt="Xeta Solutions Logo" class="h-6 w-auto" style="height: 24px;">
      </div>

      <p class="mt-2 text-xs">
        <small>This is an automated email. Please do not reply.</small>
      </p>
    </div>
  </div>
</body>
</html>


                    `
                });
            }
        })().catch(err => console.error("Email sending failed:", err)); // Log email errors

        res.status(201).json({ message: "Interview event created and notifications sent successfully!" });

    } catch (error) {
        console.error("Schedule Interview Error:", error);
        res.status(500).json({ message: 'Server error saving the schedule.' });
    }
});


// =================================================================
// --- HIRING MODERATOR: REPORTING ENDPOINTS ---
// =================================================================

/**
 * @route   GET /api/hiring/interview-events
 * @desc    Moderator: Gets all interview events they created
 * @access  Private (Hiring Moderator)
 */
app.get('/api/hiring/interview-events', hiringModeratorAuth, async (req, res) => {
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: HIRING_INTERVIEWS_TABLE,
            FilterExpression: "begins_with(PK, :event_prefix) AND SK = :meta AND createdBy = :email",
            ExpressionAttributeValues: {
                ":event_prefix": "EVENT_",
                ":meta": "METADATA",
                ":email": req.user.email
            }
        }));
        
        // Sort by date, newest first
        Items.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        res.json(Items);

    } catch (error) {
        console.error("Get Interview Events Error:", error);
        res.status(500).json({ message: 'Server error fetching interview events.' });
    }
});

/**
 * @route   GET /api/hiring/interview-report/:eventId
 * @desc    Moderator: Gets all evaluations for a specific event
 * @access  Private (Hiring Moderator)
 */
app.get('/api/hiring/interview-report/:eventId', hiringModeratorAuth, async (req, res) => {
    const { eventId } = req.params;

    try {
        // 1. Check if moderator owns this event
        const { Item: event } = await docClient.send(new GetCommand({
            TableName: HIRING_INTERVIEWS_TABLE,
            Key: { PK: eventId, SK: "METADATA" }
        }));
        if (!event || event.createdBy !== req.user.email) {
            return res.status(403).json({ message: "Access denied or event not found." });
        }

        // 2. Fetch all evaluations for this event using the GSI
        const { Items } = await docClient.send(new QueryCommand({
            TableName: HIRING_INTERVIEWS_TABLE,
            IndexName: "GSI1Index",
            KeyConditionExpression: "GSI1_PK = :pk",
            ExpressionAttributeValues: {
                ":pk": `REPORT#${eventId}`
            }
        }));

        // 3. Respond with the event metadata and the fetched evaluations
        res.json({
            eventId: event.eventId,
            eventName: event.eventName,
            jobTitle: event.jobTitle,
            createdAt: event.createdAt,
            evaluations: Items || []
        });

    } catch (error) {
        console.error(`Error fetching report for ${eventId}:`, error);
        res.status(500).json({ message: 'Server error fetching report.' });
    }
});


// =================================================================
// --- INTERVIEWER PORTAL ENDPOINTS ---
// =================================================================

/**
 * @route   GET /api/interviewer/my-schedule
 * @desc    Get the assigned interview schedule for the logged-in interviewer
 * @access  Private (Interviewer)
 */
app.get('/api/interviewer/my-schedule', interviewerAuth, async (req, res) => {
    const interviewerEmail = req.user.email;
    try {
        // (Ensuring GSI1Index is correct)
        const { Items } = await docClient.send(new QueryCommand({
            TableName: HIRING_INTERVIEWS_TABLE,
            IndexName: "GSI1Index",
            KeyConditionExpression: "GSI1_PK = :email",
            FilterExpression: "begins_with(SK, :slot_prefix)",
            ExpressionAttributeValues: {
                ":email": interviewerEmail,
                ":slot_prefix": "SLOT#"
            }
        }));

        if (!Items || Items.length === 0) {
            return res.json([]);
        }
        
        const now = new Date();
        const schedule = Items.map(item => {
            let status = 'Upcoming';
            const startTime = new Date(item.startTime);
            const endTime = new Date(item.endTime);

            if (item.interviewStatus === 'COMPLETED') {
                status = 'Completed';
            } else if (item.interviewStatus === 'ACTIVE') {
                status = 'Active'; // Show as active if manually started
            } else if (now >= startTime && now < endTime) {
                status = 'Active'; // Show as active if in time window
            } else if (now > endTime) {
                status = 'Pending Evaluation'; 
            }

            return {
                slotId: item.slotId,
                candidateName: item.candidateName,
                candidateEmail: item.candidateEmail,
                startTime: item.startTime,
                status: status
            };
        });

        schedule.sort((a, b) => new Date(a.startTime) - new Date(b.startTime));
        res.json(schedule);

    } catch (error) {
        console.error(`[GET /api/interviewer/my-schedule] Error:`, error);
        res.status(500).json({ message: 'Server error fetching schedule.' });
    }
});


/**
 * @route   GET /api/interviewer/slot-details/:slotId
 * @desc    Interviewer: Get details for a specific interview slot (candidate resume, photo, etc)
 * @access  Private (Interviewer)
 */
app.get('/api/interviewer/slot-details/:slotId', interviewerAuth, async (req, res) => {
    const { slotId } = req.params;
    const interviewerEmail = req.user.email;

    try {
        // 1. Fetch the slot (Ensuring GSI2Index is correct)
        const { Items } = await docClient.send(new QueryCommand({
            TableName: HIRING_INTERVIEWS_TABLE,
            IndexName: "GSI2Index", 
            KeyConditionExpression: "GSI2_PK = :sid",
            ExpressionAttributeValues: { ":sid": slotId }
        }));

        if (!Items || Items.length === 0) {
            return res.status(404).json({ message: "Slot not found." });
        }
        const slotData = Items[0];

        // 2. Security Check
        if (slotData.interviewerEmail !== interviewerEmail) {
            return res.status(403).json({ message: "Access denied. You are not assigned to this slot." });
        }

        // 3. Fetch the candidate's application (which has the resume)
        const { Items: applications } = await docClient.send(new QueryCommand({
            TableName: HIRING_APPLICATIONS_TABLE,
            IndexName: "email-jobId-index", 
            KeyConditionExpression: "email = :email AND jobId = :jobId",
            ExpressionAttributeValues: {
                ":email": slotData.candidateEmail,
                ":jobId": slotData.jobId
            }
        }));

        let applicationData = {};
        if (applications && applications.length > 0) {
            applicationData = applications[0]; // Get the first matching application
        }
        
        // 4. Get Interviewer Photo (from their TestifyUsers profile)
        let interviewerPhotoUrl = null;
        try {
             const { Item: interviewer } = await docClient.send(new GetCommand({
                 TableName: "TestifyUsers",
                 Key: { email: interviewerEmail }
             }));
             if (interviewer && interviewer.profileImageUrl) {
                 interviewerPhotoUrl = interviewer.profileImageUrl;
             }
        } catch (e) { console.error("Could not fetch interviewer photo", e); }


        // --- CORRECTED RESPONSE: Includes all state data for robust restoration ---
        res.json({
            slot: { ...slotData },
            application: applicationData,
            interviewerPhotoUrl: interviewerPhotoUrl,
            
            // State Restoration Data (Crucial for Robustness)
            chatHistory: slotData.chatHistory || [],
            assignedProblems: slotData.assignedProblems || [], 
            latestCode: slotData.latestCode || '',
            latestLanguage: slotData.latestLanguage || 'javascript',
            currentProblemId: slotData.currentProblemId || null
        });

    } catch (error) {
        console.error(`Error fetching slot details ${slotId}:`, error);
        res.status(500).json({ message: 'Server error fetching slot details.' });
    }
});


/**
 * @route   GET /api/interviewer/coding-problems
 * @desc    Interviewer: Get all coding problems (for assigning)
 * @access  Private (Interviewer)
 */
app.get('/api/interviewer/coding-problems', interviewerAuth, async (req, res) => {
    try {
        // This fetches ALL problems from the hiring problems table.
        // You could scope this by `createdBy` if needed.
        const { Items } = await docClient.send(new ScanCommand({
            TableName: HIRING_CODING_PROBLEMS_TABLE
        }));
        // Map problemId to id for frontend compatibility
        res.json((Items || []).map(p => ({ ...p, id: p.problemId })));
    } catch (error) {
        console.error("Get Interviewer Coding Problems Error:", error);
        res.status(500).json({ message: 'Server error fetching coding problems.' });
    }
});


/**
 * @route   POST /api/interviewer/start-interview
 * @desc    Interviewer: Clicks "Start" to begin the interview
 * @access  Private (Interviewer)
 */
app.post('/api/interviewer/start-interview', interviewerAuth, async (req, res) => {
    const { slotId } = req.body;
    if (!slotId) return res.status(400).json({ message: 'Slot ID is required.' });

    try {
        // 1. Find the slot item (using GSI2)
        const { Items } = await docClient.send(new QueryCommand({
            TableName: HIRING_INTERVIEWS_TABLE,
            IndexName: "GSI2Index",
            KeyConditionExpression: "GSI2_PK = :sid",
            ExpressionAttributeValues: { ":sid": slotId }
        }));

        if (!Items || Items.length === 0) {
            return res.status(404).json({ message: "Slot not found." });
        }
        const slotItem = Items[0];
        
        // 2. Security Check
        if (slotItem.interviewerEmail !== req.user.email) {
             return res.status(403).json({ message: 'Access denied.' });
        }

        // 3. Update slot status to ACTIVE
        await docClient.send(new UpdateCommand({
            TableName: HIRING_INTERVIEWS_TABLE,
            Key: {
                PK: slotItem.PK,
                SK: slotItem.SK
            },
            UpdateExpression: "SET interviewStatus = :status",
            ExpressionAttributeValues: { ":status": "ACTIVE" }
        }));
        
        // 4. Emit socket event to student
        io.to(slotId).emit('interview-started');
        
        res.status(200).json({ message: 'Interview started.' });
    
    } catch (error) {
        console.error(`Error starting interview ${slotId}:`, error);
        res.status(500).json({ message: 'Server error starting interview.' });
    }
});


/**
 * @route   POST /api/interviewer/submit-evaluation
 * @desc    Interviewer: Submits the final evaluation for a candidate
 * @access  Private (Interviewer)
 */
app.post('/api/interviewer/submit-evaluation', interviewerAuth, async (req, res) => {
    // The evaluation object now contains the full 7-point breakdown + totalScore, recommendation, feedback, and notes.
    const { slotId, evaluation, studentDetails } = req.body; 
    const interviewerEmail = req.user.email;

    // --- CRITICAL: Added validation for the mandatory fields ---
    if (!slotId || !evaluation || !evaluation.recommendation || !evaluation.feedback) {
        return res.status(400).json({ message: 'Slot ID, recommendation, and detailed feedback are required.' });
    }

    try {
        // 1. Get the slot data (which has all the saved state like chatHistory, latestCode)
        const { Items } = await docClient.send(new QueryCommand({
            TableName: HIRING_INTERVIEWS_TABLE,
            IndexName: "GSI2Index",
            KeyConditionExpression: "GSI2_PK = :sid",
            ExpressionAttributeValues: { ":sid": slotId }
        }));
        if (!Items || Items.length === 0) {
            return res.status(404).json({ message: "Slot not found." });
        }
        const slotData = Items[0];
        
        // 2. Security Check
        if (slotData.interviewerEmail !== interviewerEmail) {
            return res.status(403).json({ message: "Access denied to this slot." });
        }

        // --- 3. Compile Interview Summary & Final Evaluation Item ---
        const evalId = `EVAL_${slotId}`;
        const evaluationItem = {
            PK: slotData.PK, 
            SK: `EVAL#${new Date().toISOString()}`, // Unique key for the evaluation record
            GSI1_PK: `REPORT#${slotData.eventId}`, // GSI for moderator to query all reports
            GSI1_SK: `EVAL#${slotData.candidateEmail}`,
            GSI2_PK: slotData.jobId, // Allows querying all evals for a specific job
            GSI2_SK: `EVAL#${slotData.candidateEmail}`,

            evalId,
            slotId,
            eventId: slotData.eventId,
            jobId: slotData.jobId,
            jobTitle: slotData.jobTitle,
            interviewerEmail,
            candidateEmail: slotData.candidateEmail,
            candidateName: slotData.candidateName,
            
            // --- Evaluation Data (7-point criteria structure) ---
            evaluation: {
                ...evaluation,
                // Ensure all 7 points are explicitly saved
                technicalKnowledge: evaluation.technicalKnowledge || 0,
                problemSolving: evaluation.problemSolving || 0,
                projectUnderstanding: evaluation.projectUnderstanding || 0,
                communicationSkills: evaluation.communicationSkills || 0,
                attitudeBehavior: evaluation.attitudeBehavior || 0,
                analyticalThinking: evaluation.analyticalThinking || 0,
                overallImpression: evaluation.overallImpression || 0,
            },

            // --- Persistent Contextual Data ---
            studentDetails: studentDetails || slotData.studentDetails || {},
            submittedCode: slotData.latestCode || "", 
            submittedCodeLanguage: slotData.latestLanguage || "javascript",
            chatHistory: slotData.chatHistory || [],
            assignedProblems: slotData.assignedProblems || [],

            submittedAt: new Date().toISOString(),
            status: "SUBMITTED"
        };

        // 4. Save the Evaluation Item
        await docClient.send(new PutCommand({
            TableName: HIRING_INTERVIEWS_TABLE,
            Item: evaluationItem
        }));

        // 5. Update the original slot item to mark as COMPLETED
        await docClient.send(new UpdateCommand({
            TableName: HIRING_INTERVIEWS_TABLE,
            Key: {
                PK: slotData.PK,
                SK: slotData.SK
            },
            UpdateExpression: "set interviewStatus = :status",
            ExpressionAttributeValues: {
                ":status": "COMPLETED"
            }
        }));
        
        res.status(201).json({ message: "Evaluation submitted successfully." });

    } catch (error) {
        console.error(`Error submitting evaluation for ${slotId}:`, error);
        res.status(500).json({ message: 'Server error submitting evaluation.' });
    }
});



// =================================================================
// --- STUDENT/PUBLIC: INTERVIEW ROOM ENDPOINT ---
// =================================================================

/**
 * @route   POST /api/public/student-details
 * @desc    Student: Submits their pre-interview details and photo
 * @access  Private (Token)
 */
app.post('/api/public/student-details', authMiddleware, async (req, res) => {
    if (!req.user || !req.user.isExternal || !req.user.slotId) {
        return res.status(403).json({ message: 'Invalid token.' });
    }
    
    const { slotId } = req.user;
    const { 
        candidateName, 
        candidateEmail, 
        rollNumber, 
        collegeName, 
        departmentName, 
        photo // base64 string
    } = req.body;

    if (!candidateName || !candidateEmail || !rollNumber || !collegeName || !departmentName || !photo) {
        return res.status(400).json({ message: 'All fields and a photo are required.' });
    }

    try {
        // --- 1. Upload Photo to S3 ---
        const photoBuffer = Buffer.from(photo.replace(/^data:image\/jpeg;base64,/, ""), 'base64');
        const fileKey = `student-photos/${slotId}_${uuidv4()}.jpg`;

        const s3Params = {
            Bucket: STUDENT_PHOTOS_BUCKET,
            Key: fileKey,
            Body: photoBuffer,
            ContentType: 'image/jpeg'
            // ACL: 'public-read' // Add this if your bucket isn't public by default
        };
        
        await s3Client.send(new PutObjectCommand(s3Params));
        const s3Url = `https://${STUDENT_PHOTOS_BUCKET}.s3.${AWS_S3_REGION}.amazonaws.com/${fileKey}`;

        // --- 2. Find the slot item to update (using GSI2) ---
        const { Items } = await docClient.send(new QueryCommand({
            TableName: HIRING_INTERVIEWS_TABLE,
            IndexName: "GSI2Index",
            KeyConditionExpression: "GSI2_PK = :sid",
            ExpressionAttributeValues: { ":sid": slotId }
        }));

        if (!Items || Items.length === 0) {
            return res.status(404).json({ message: "Interview slot not found." });
        }
        const slotItem = Items[0];
        
        // --- 3. Create the studentDetails object ---
        const studentDetails = {
            candidateName,
            candidateEmail,
            rollNumber,
            collegeName,
            departmentName,
            candidatePhotoUrl: s3Url
        };

        // --- 4. Update the slot item with the new details ---
        await docClient.send(new UpdateCommand({
            TableName: HIRING_INTERVIEWS_TABLE,
            Key: {
                PK: slotItem.PK,
                SK: slotItem.SK
            },
            // Save the object and mark details as submitted
            UpdateExpression: "SET studentDetails = :details, studentDetailsSubmitted = :true, candidateName = :name, candidateEmail = :email, rollNumber = :roll, collegeName = :college, departmentName = :dept, candidatePhotoUrl = :photo",
            ExpressionAttributeValues: {
                ":details": studentDetails,
                ":true": true,
                ":name": candidateName,
                ":email": candidateEmail,
                ":roll": rollNumber,
                ":college": collegeName,
                ":dept": departmentName,
                ":photo": s3Url
            }
        }));

        res.status(200).json({ message: 'Details submitted successfully.' });

    } catch (error) {
        console.error(`Error saving student details for ${slotId}:`, error);
        res.status(500).json({ message: 'Server error saving details.' });
    }
});


/**
 * @route   GET /api/public/interview-details
 * @desc    Student: Gets details to join their interview room (via token)
 * @access  Private (Token)
 */
/**
 * @route   GET /api/public/interview-details
 * @desc    Student: Gets details to join their interview room (via token)
 * @access  Private (Token)
 */
app.get('/api/public/interview-details', authMiddleware, async (req, res) => {
    // authMiddleware verifies the token. req.user is populated from it.
    if (!req.user || !req.user.isExternal || !req.user.slotId) {
        return res.status(403).json({ message: 'Access denied. Invalid or missing interview token.' });
    }

    const { slotId, email: candidateEmail, interviewerEmail } = req.user;
    
    // --- NEW: Get current server time ---
    const now = new Date();

    try {
        // 1. Fetch the slot (Ensuring GSI2Index is correct)
        const { Items } = await docClient.send(new QueryCommand({
            TableName: HIRING_INTERVIEWS_TABLE,
            IndexName: "GSI2Index",
            KeyConditionExpression: "GSI2_PK = :sid",
            ExpressionAttributeValues: { ":sid": slotId }
        }));

        if (!Items || Items.length === 0) {
            return res.status(404).json({ message: "Interview slot not found." });
        }
        const slotData = Items[0];

        // 2. Validate token data against slot data
        if (slotData.interviewerEmail !== interviewerEmail) {
             console.warn(`Token/Slot interviewer mismatch for ${slotId}`);
        }
        
        // If details *have* been submitted, use the email from the DB
        if (slotData.studentDetailsSubmitted) {
             if (slotData.candidateEmail !== candidateEmail) {
                console.warn(`Token/Slot candidate email mismatch for ${slotId} (using DB email)`);
             }
        } 
        // If details have *not* been submitted, use the email from the *original* slot booking
        else if (slotData.candidateEmail !== candidateEmail) {
            console.warn(`Token/Slot candidate email mismatch for ${slotId} (pre-submission)`);
            return res.status(403).json({ message: "Token details do not match interview slot." });
        }


        // 3. Check Status (NEW)
        if (slotData.interviewStatus === 'COMPLETED') {
             return res.status(410).json({ // 410 Gone
                 message: "This interview has already been completed.",
                 roomState: "COMPLETED", // Send final state
                 status: "COMPLETED"
             });
        }

        // 4. Get Interviewer Photo (NEW)
        let interviewerPhotoUrl = null;
        try {
             const { Item: interviewer } = await docClient.send(new GetCommand({
                 TableName: "TestifyUsers",
                 Key: { email: slotData.interviewerEmail }
             }));
             if (interviewer && interviewer.profileImageUrl) { 
                 interviewerPhotoUrl = interviewer.profileImageUrl;
             }
        } catch (e) { console.error("Could not fetch interviewer photo", e); }


        // --- NEW LOBBY LOGIC ---
        const startTime = new Date(slotData.startTime);
        const timeToStartMs = startTime.getTime() - now.getTime();
        const TEN_MINUTES_MS = 10 * 60 * 1000;
        
        let roomState = 'LOBBY'; // Default state is Lobby

        if (slotData.studentDetailsSubmitted === false) {
            // Student has not submitted details yet
            if (timeToStartMs <= TEN_MINUTES_MS) {
                // It's 10 minutes (or less) before the interview, or past start time
                // Time to collect details.
                roomState = 'DETAILS_FORM';
            } else {
                // It's more than 10 minutes before. Stay in lobby.
                roomState = 'LOBBY';
            }
        } else {
            // Student HAS submitted details. Check if interviewer is ready.
            if (slotData.interviewStatus === 'ACTIVE') {
                // Interviewer clicked "Start". Student can join.
                roomState = 'INTERVIEW_ROOM';
            } else {
                // Interviewer has not clicked "Start". Student must wait,
                // even if the interview time has arrived.
                roomState = 'LOBBY';
            }
        }
        // --- END OF NEW LOBBY LOGIC ---


        // 5. Send back the necessary details
        res.json({
            // --- NEW/MODIFIED FIELDS ---
            roomState: roomState,            // 'LOBBY', 'DETAILS_FORM', 'INTERVIEW_ROOM'
            serverTime: now.toISOString(), // So frontend can sync its timer
            // --- EXISTING FIELDS ---
            slotId: slotData.slotId,
            interviewerName: slotData.interviewerName,
            interviewerPhotoUrl: interviewerPhotoUrl,
            startTime: slotData.startTime,
            endTime: slotData.endTime,
            status: slotData.interviewStatus, // e.g., "UPCOMING", "ACTIVE"
            studentDetailsSubmitted: slotData.studentDetailsSubmitted || false,
            
            // Student Details (if submitted, from studentDetails object)
            // Fallback to top-level slotData for pre-submission
            studentDetails: slotData.studentDetails || {
                candidateName: slotData.candidateName || null,
                candidateEmail: slotData.candidateEmail || null,
                rollNumber: slotData.rollNumber || null,
                collegeName: slotData.collegeName || null,
                departmentName: slotData.departmentName || null,
                candidatePhotoUrl: slotData.candidatePhotoUrl || null
            },
            
            // State Restoration Data
            chatHistory: slotData.chatHistory || [],
            assignedProblems: slotData.assignedProblems || [],
            latestCode: slotData.latestCode || '',
            latestLanguage: slotData.latestLanguage || 'javascript',
            currentProblemId: slotData.currentProblemId || null
        });

    } catch (error) {
        console.error(`Error fetching public interview details for ${slotId}:`, error);
        res.status(500).json({ message: 'Server error fetching interview details.' });
    }
});
// THIS ENDPOINT IS FROM THE USER'S PROMPT but seems to be for a different data structure
// I am including it as requested.
app.get('/api/hiring/job-pool-applicants/:jobId/:poolName', hiringModeratorAuth, async (req, res) => {
    const { jobId, poolName } = req.params;
    const moderatorEmail = req.user.email;

    try {
        // First, verify the moderator owns this job
        const { Item: job } = await docClient.send(new GetCommand({
            TableName: JOBS_TABLE, // This is 'HiringJobs'
            Key: { jobId: jobId } // Assuming PK is 'jobId'
        }));

        if (!job || job.createdBy !== moderatorEmail) {
            return res.status(403).json({ message: "Access denied. You do not own this job." });
        }

        // Fetch applicants from the specified pool
        // This query implies a GSI on APPLICATIONS_TABLE ('HiringApplications')
        // called 'JobPoolIndex' with GSI1_PK = 'JOB#[jobId]' and GSI1_SK = 'POOL#[poolName]'
        // This is a different structure than the one used elsewhere.
        const { Items } = await docClient.send(new QueryCommand({
            TableName: APPLICATIONS_TABLE, // This is 'HiringApplications'
            IndexName: "JobPoolIndex", // Using the GSI
            KeyConditionExpression: "GSI1_PK = :pk and GSI1_SK = :sk",
            ExpressionAttributeValues: {
                ":pk": `JOB#${jobId}`,
                ":sk": `POOL#${poolName}`
            },
            ProjectionExpression: "applicantEmail" // Only get the emails
        }));

        const emails = Items.map(item => item.applicantEmail);
        res.json({ emails: emails });

    } catch (error) {
        console.error(`Error fetching applicants for job ${jobId}, pool ${poolName}:`, error);
        res.status(500).json({ message: "Server error fetching applicants." });
    }
});
app.get('/api/public/interview-problem-details/:problemId', authMiddleware, async (req, res) => {
    // 1. Check for interview token
    if (!req.user || !req.user.isExternal || !req.user.slotId) {
        return res.status(403).json({ message: 'Access denied. Invalid interview token.' });
    }
    
    const { problemId } = req.params;
    const { slotId, email: candidateEmail } = req.user;

    try {
        // 2. Fetch the interview slot
        const { Items } = await docClient.send(new QueryCommand({
            TableName: HIRING_INTERVIEWS_TABLE, // Your "HiringInterviews" table
            IndexName: "GSI2Index", // GSI on slotId
            KeyConditionExpression: "GSI2_PK = :sid",
            ExpressionAttributeValues: { ":sid": slotId }
        }));

        if (!Items || Items.length === 0) {
            return res.status(404).json({ message: "Interview slot not found." });
        }
        const slotData = Items[0];

        // 3. Security Check: Verify this problem was actually assigned by the interviewer
        // We check against the `assignedProblems` array in the slot data.
        if (!slotData.assignedProblems || !Array.isArray(slotData.assignedProblems)) {
             return res.status(403).json({ message: "No problems are assigned for this slot." });
        }

        // Find the problem in the assigned list (we check by 'id' or 'problemId')
        const isAssigned = slotData.assignedProblems.some(p => p.id === problemId || p.problemId === problemId);

        if (!isAssigned) {
            console.warn(`[Interview Problem] Attack attempt? Candidate ${candidateEmail} tried to fetch unassigned problem ${problemId} for slot ${slotId}`);
            return res.status(403).json({ message: "Access denied. This problem is not assigned to you." });
        }

        // 4. Fetch the full problem details
        const { Item: fullProblemData } = await docClient.send(new GetCommand({
            TableName: HIRING_CODING_PROBLEMS_TABLE, // Your "HiringCodingProblems" table
            Key: { problemId: problemId } // PK of the problems table
        }));

        if (!fullProblemData) {
            return res.status(404).json({ message: "Problem details not found." });
        }
        
        // 5. Send the problem data to the student
        res.json(fullProblemData);

    } catch (error) {
        console.error(`Error fetching interview problem details for ${problemId} (Slot: ${slotId}):`, error);
        res.status(500).json({ message: 'Server error fetching problem details.' });
    }
});

app.get('/api/interviewer/coding-problems/:problemId', interviewerAuth, async (req, res) => {
    const { problemId } = req.params;
    
    // NOTE: HIRING_CODING_PROBLEMS_TABLE must be defined and accessible.
    // Example: const HIRING_CODING_PROBLEMS_TABLE = "HiringCodingProblems";

    try {
        // 1. Fetch the full problem details using the problemId as the primary key
        const { Item: fullProblemData } = await docClient.send(new GetCommand({
            TableName: HIRING_CODING_PROBLEMS_TABLE, 
            Key: { problemId: problemId }
        }));

        if (!fullProblemData) {
            console.warn(`[GET PROBLEM] Problem details not found for ID: ${problemId}`);
            return res.status(404).json({ message: "Coding problem details not found." });
        }
        
        // 2. Return the full problem data (frontend handles display)
        res.json({ ...fullProblemData, id: problemId }); // Map to 'id' for consistency

    } catch (error) {
        console.error(`[GET PROBLEM] Error fetching details for ${problemId}:`, error);
        res.status(500).json({ message: 'Server error fetching problem details.' });
    }
});
const smeAuth = async (req, res, next) => {
    // This middleware assumes authMiddleware has already run and populated req.user
    await authMiddleware(req, res, () => {
        if (req.user && req.user.role === 'SME') {
            next();
        } else if (!res.headersSent) {
             res.status(403).json({ message: 'Access denied. SME role required.' });
        }
    });
};


// --- 3. Add new API endpoints for Admin to manage SMEs ---
// Place these near your other admin or user management routes

/**
 * @route   POST /api/admin/smes
 * @desc    Admin: Create a new Subject Matter Expert (SME)
 * @access  Private (Admin Only)
 */
app.post('/api/admin/smes', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }

    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) {
        return res.status(400).json({ message: 'Please provide full name, email, and password.' });
    }

    try {
        const emailLower = email.toLowerCase();
        // We use 'TestifyUsers' as it holds Admin and Moderator logins
        const existingUser = await docClient.send(new GetCommand({ 
            TableName: "TestifyUsers", 
            Key: { email: emailLower } 
        }));
        
        if (existingUser.Item) {
            return res.status(400).json({ message: 'User with this email already exists.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newSme = {
            email: emailLower,
            fullName,
            password: hashedPassword,
            role: "SME", // The new role
            isBlocked: false,
            createdAt: new Date().toISOString()
        };

        await docClient.send(new PutCommand({ 
            TableName: "TestifyUsers", 
            Item: newSme 
        }));
        
        res.status(201).json({ message: 'SME account created successfully!' });
    } catch (error) {
        console.error("Create SME Error:", error);
        res.status(500).json({ message: 'Server error during SME creation.' });
    }
});

/**
 * @route   GET /api/admin/smes
 * @desc    Admin: Get all SME accounts
 * @access  Private (Admin Only)
 */
app.get('/api/admin/smes', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    
    try {
        const { Items } = await docClient.send(new ScanCommand({
            TableName: "TestifyUsers",
            FilterExpression: "#role = :role",
            ExpressionAttributeNames: { "#role": "role" },
            ExpressionAttributeValues: { ":role": "SME" }
        }));
        
        // Return all SMEs, but remove their passwords
        res.json(Items.map(({ password, ...rest }) => rest));
    } catch (error) {
        console.error("Get SMEs Error:", error);
        res.status(500).json({ message: 'Server error fetching SME accounts.' });
    }
});

/**
 * @route   DELETE /api/admin/smes/:email
 * @desc    Admin: Delete an SME account
 * @access  Private (Admin Only)
 */
app.delete('/api/admin/smes/:email', authMiddleware, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    
    const { email } = req.params;
    if (!email) {
        return res.status(400).json({ message: 'Email is required.'});
    }

    try {
        // You might want to add a check here to ensure an Admin isn't deleting another Admin
        const { Item } = await docClient.send(new GetCommand({ 
            TableName: "TestifyUsers", 
            Key: { email: email.toLowerCase() } 
        }));
        
        if (!Item) {
             return res.status(404).json({ message: 'User not found.' });
        }
        
        if (Item.role !== 'SME') {
             return res.status(400).json({ message: 'This account is not an SME account.' });
        }

        await docClient.send(new DeleteCommand({
            TableName: "TestifyUsers",
            Key: { email: email.toLowerCase() }
        }));
        
        res.json({ message: 'SME account deleted successfully.' });
    } catch (error) {
        console.error("Delete SME Error:", error);
        res.status(500).json({ message: 'Server error deleting SME account.' });
    }
});

// =================================================================
// --- SME (SUBJECT MATTER EXPERT) PORTAL API ENDPOINTS ---
// =================================================================

// --- 1. SME Coding Problem Management ---
// (Uses HIRING_CODING_PROBLEMS_TABLE)

// SME: Create a new coding problem
app.post('/api/sme/coding-problems', smeAuth, async (req, res) => {
    const { title, description, difficulty, score, inputFormat, outputFormat, constraints, example, testCases } = req.body;
    if (!title || !description || !difficulty || !score || !testCases || testCases.length === 0) {
        return res.status(400).json({ message: 'Missing required problem fields.' });
    }
    const problemId = `hire_problem_${uuidv4()}`;
    const newProblem = {
        problemId, title, description, difficulty, score: parseInt(score, 10), 
        inputFormat, outputFormat, constraints, example, testCases,
        createdBy: req.user.email, // Link problem to the SME
        createdAt: new Date().toISOString()
    };
    try {
        await docClient.send(new PutCommand({ TableName: HIRING_CODING_PROBLEMS_TABLE, Item: newProblem }));
        res.status(201).json({ message: 'Coding problem created!', problem: newProblem });
    } catch (error) {
        console.error("SME Create Coding Problem Error:", error);
        res.status(500).json({ message: 'Server error creating problem.' });
    }
});

// SME: Get *only* their own coding problems
app.get('/api/sme/coding-problems', smeAuth, async (req, res) => {
    try {
        // Use the GSI 'createdBy-index' to fetch only problems made by this SME
        const { Items } = await docClient.send(new QueryCommand({
            TableName: HIRING_CODING_PROBLEMS_TABLE,
            IndexName: "createdBy-index", // Assumes this GSI exists
            KeyConditionExpression: "createdBy = :creator",
            ExpressionAttributeValues: { ":creator": req.user.email }
        }));
        res.json(Items || []);
    } catch (error) {
        console.error("SME Get Coding Problems Error:", error);
        res.status(500).json({ message: 'Server error fetching problems.' });
    }
});

// SME: Update their own coding problem
app.put('/api/sme/coding-problems/:problemId', smeAuth, async (req, res) => {
    const { problemId } = req.params;
    const { title, description, difficulty, score, inputFormat, outputFormat, constraints, example, testCases } = req.body;

    try {
        const { Item: existingProblem } = await docClient.send(new GetCommand({
            TableName: HIRING_CODING_PROBLEMS_TABLE,
            Key: { problemId }
        }));

        if (!existingProblem) {
            return res.status(404).json({ message: 'Problem not found.' });
        }
        if (existingProblem.createdBy !== req.user.email) {
            return res.status(403).json({ message: 'Access denied. You can only edit your own problems.' });
        }

        const updatedProblem = {
            ...existingProblem,
            title, description, difficulty, score: parseInt(score, 10),
            inputFormat, outputFormat, constraints, example, testCases,
            updatedAt: new Date().toISOString()
        };

        await docClient.send(new PutCommand({ TableName: HIRING_CODING_PROBLEMS_TABLE, Item: updatedProblem }));
        res.status(200).json({ message: 'Coding problem updated successfully!' });
    } catch (error) {
        console.error("SME Update Coding Problem Error:", error);
        res.status(500).json({ message: 'Server error updating problem.' });
    }
});

// SME: Delete their own coding problem
app.delete('/api/sme/coding-problems/:problemId', smeAuth, async (req, res) => {
    const { problemId } = req.params;
    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: HIRING_CODING_PROBLEMS_TABLE,
            Key: { problemId }
        }));
        if (!Item || Item.createdBy !== req.user.email) {
            return res.status(403).json({ message: 'Access denied.' });
        }
        await docClient.send(new DeleteCommand({
            TableName: HIRING_CODING_PROBLEMS_TABLE,
            Key: { problemId }
        }));
        res.status(200).json({ message: 'Coding problem deleted.' });
    } catch (error) {
        console.error("SME Delete Coding Problem Error:", error);
        res.status(500).json({ message: 'Server error deleting problem.' });
    }
});

// --- 2. SME Aptitude Test Management ---
// (Uses HIRING_APTITUDE_TESTS_TABLE)

// SME: Create a new aptitude test
app.post('/api/sme/aptitude-tests', smeAuth, async (req, res) => {
    const { testTitle, duration, totalMarks, passingPercentage, sections, useSectionSettings } = req.body;
    const aptitudeTestId = `hire_apt_${uuidv4()}`;
    
    const newTest = {
        aptitudeTestId,
        title: testTitle,
        duration: parseInt(duration, 10),
        totalMarks: parseInt(totalMarks, 10),
        passingPercentage: parseInt(passingPercentage, 10),
        sections,
        useSectionSettings: useSectionSettings || false,
        createdBy: req.user.email, // Link test to the SME
        createdAt: new Date().toISOString()
    };

    try {
        await docClient.send(new PutCommand({ TableName: HIRING_APTITUDE_TESTS_TABLE, Item: newTest }));
        res.status(201).json({ message: 'Aptitude test created!', test: newTest });
    } catch (error) {
        console.error("SME Create Aptitude Test Error:", error);
        res.status(500).json({ message: 'Server error creating aptitude test.' });
    }
});

// SME: Get *only* their own aptitude tests
app.get('/api/sme/aptitude-tests', smeAuth, async (req, res) => {
    try {
        const { Items } = await docClient.send(new QueryCommand({
            TableName: HIRING_APTITUDE_TESTS_TABLE,
            IndexName: "createdBy-index", // Assumes this GSI exists
            KeyConditionExpression: "createdBy = :creator",
            ExpressionAttributeValues: { ":creator": req.user.email }
        }));
        res.json(Items || []);
    } catch (error) {
        console.error("SME Get Aptitude Tests Error:", error);
        res.status(500).json({ message: 'Server error fetching aptitude tests.' });
    }
});

// SME: Get one of their aptitude tests (for editing)
app.get('/api/sme/aptitude-tests/:aptitudeTestId', smeAuth, async (req, res) => {
    const { aptitudeTestId } = req.params;
    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: HIRING_APTITUDE_TESTS_TABLE,
            Key: { aptitudeTestId }
        }));
        if (!Item || Item.createdBy !== req.user.email) {
            return res.status(404).json({ message: 'Aptitude test not found or access denied.' });
        }
        res.json(Item);
    } catch (error) {
        console.error("SME Get Single Aptitude Test Error:", error);
        res.status(500).json({ message: 'Server error fetching test.' });
    }
});

// SME: Update their own aptitude test
app.put('/api/sme/aptitude-tests/:aptitudeTestId', smeAuth, async (req, res) => {
    const { aptitudeTestId } = req.params;
    const { testTitle, duration, totalMarks, passingPercentage, sections, useSectionSettings } = req.body;
    
    try {
        const { Item: existingTest } = await docClient.send(new GetCommand({
            TableName: HIRING_APTITUDE_TESTS_TABLE,
            Key: { aptitudeTestId }
        }));
        if (!existingTest || existingTest.createdBy !== req.user.email) {
            return res.status(403).json({ message: 'Access denied.' });
        }

        const updatedTest = {
            ...existingTest,
            title: testTitle,
            duration: parseInt(duration, 10),
            totalMarks: parseInt(totalMarks, 10),
            passingPercentage: parseInt(passingPercentage, 10),
            sections,
            useSectionSettings: useSectionSettings || false,
            updatedAt: new Date().toISOString()
        };

        await docClient.send(new PutCommand({ TableName: HIRING_APTITUDE_TESTS_TABLE, Item: updatedTest }));
        res.status(200).json({ message: 'Aptitude test updated!', test: updatedTest });
    } catch (error) {
        console.error("SME Update Aptitude Test Error:", error);
        res.status(500).json({ message: 'Server error updating test.' });
    }
});

// SME: Delete their own aptitude test
app.delete('/api/sme/aptitude-tests/:aptitudeTestId', smeAuth, async (req, res) => {
    const { aptitudeTestId } = req.params;
    try {
        const { Item } = await docClient.send(new GetCommand({
            TableName: HIRING_APTITUDE_TESTS_TABLE,
            Key: { aptitudeTestId }
        }));
        if (!Item || Item.createdBy !== req.user.email) {
            return res.status(403).json({ message: 'Access denied.' });
        }
        await docClient.send(new DeleteCommand({
            TableName: HIRING_APTITUDE_TESTS_TABLE,
            Key: { aptitudeTestId }
        }));
        res.status(200).json({ message: 'Aptitude test deleted.' });
    } catch (error) {
        console.error("SME Delete Aptitude Test Error:", error);
        res.status(500).json({ message: 'Server error deleting test.' });
    }
});

// --- 3. SME Helper Endpoints (AI & Media) ---

// SME: AI generation for coding problems
app.post('/api/sme/generate-problem-from-pdf', smeAuth, async (req, res) => {
    const { text } = req.body;
    if (!text) return res.status(400).json({ message: 'No text provided.' });

    try {
        // This logic is copied from your existing /api/hiring/generate-problem-from-pdf
        const prompt = `Based on the following text from a coding problem document, create a structured JSON object...`; // (Same prompt as hiring moderator)

        const schema = {
            type: "OBJECT",
            properties: {
                "title": { "type": "STRING" },
                "description": { "type": "STRING" },
                "difficulty": { "type": "STRING", "enum": ["Easy", "Medium", "Hard"] },
                 "score": { "type": "NUMBER" },
                "inputFormat": { "type": "STRING" },
                "outputFormat": { "type": "STRING" },
                "constraints": { "type": "STRING" },
                "example": { "type": "STRING" },
                "testCases": {
                    "type": "ARRAY", "items": {
                        "type": "OBJECT", "properties": {
                            "input": { "type": "STRING" },
                            "expected": { "type": "STRING" }
                        }, "required": ["input", "expected"]
                    }
                }
            },
            required: ["title", "description", "difficulty", "score", "testCases"]
        };

        const apiKey = process.env.GEMINI_API_KEY || 'AIzaSyAR_X4MZ75vxwV7OTU3dabFRcVe4SxWpb8';
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
            throw new Error(`AI API call failed: ${errorBody}`);
        }

        const result = await apiResponse.json();
        const jsonText = result.candidates[0].content.parts[0].text;
        res.json(JSON.parse(jsonText));

    } catch (error) {
        console.error('Error in SME AI problem generation:', error);
        res.status(500).json({ message: 'Failed to generate problem from AI.' });
    }
});

// SME: AI generation for aptitude tests
app.post('/api/sme/generate-test-from-pdf', smeAuth, async (req, res) => {
    const { text } = req.body;
    if (!text) return res.status(400).json({ message: 'No text provided.' });
    try {
        // This logic is copied from your existing /api/hiring/generate-test-from-pdf
        const prompt = `Based on the following text which contains questions and answers, create a complete, structured JSON object for a test...`; // (Same prompt as hiring moderator)

        const schema = {
            type: "OBJECT",
            properties: {
                "testTitle": { "type": "STRING" },
                "duration": { "type": "NUMBER" },
                "totalMarks": { "type": "NUMBER" },
                "passingPercentage": { "type": "NUMBER" },
                "sections": {
                    "type": "ARRAY", "items": {
                        "type": "OBJECT", "properties": {
                            "title": { "type": "STRING" },
                            "questions": {
                                "type": "ARRAY", "items": {
                                    "type": "OBJECT", "properties": {
                                        "text": { "type": "STRING" },
                                        "type": { "type": "STRING", "enum": ["mcq-single", "mcq-multiple", "fill-blank"] },
                                        "marks": { "type": "NUMBER" },
                                        "options": { "type": "ARRAY", "items": { "type": "STRING" } },
                                        "correctAnswer": { "type": "STRING" },
                                        "correctAnswers": { "type": "ARRAY", "items": { "type": "STRING" } }
                                    }, "required": ["text", "type", "marks"]
                                }
                            }
                        }, "required": ["title", "questions"]
                    }
                }
            },
            required: ["testTitle", "duration", "totalMarks", "passingPercentage", "sections"]
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
            throw new Error(`AI API call failed: ${errorBody}`);
        }

        const result = await apiResponse.json();
        const jsonText = result.candidates[0].content.parts[0].text;
        res.json(JSON.parse(jsonText));
    } catch (error) {
        console.error('Error in SME AI test generation:', error);
        res.status(500).json({ message: 'Failed to generate test from AI.' });
    }
});

// SME: Media upload for aptitude tests
app.post('/api/sme/upload-media', smeAuth, upload.single('mediaFile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No media file was uploaded.' });
    }
    // Create a unique folder for this SME
    const fileKey = `test-media/sme-${req.user.email}/${uuidv4()}-${req.file.originalname}`; 
    const s3Params = {
        Bucket: S3_BUCKET_NAME, // S3_BUCKET_NAME = "hirewithusjobapplications"
        Key: fileKey,
        Body: req.file.buffer,
        ContentType: req.file.mimetype
    };
    try {
        await s3Client.send(new PutObjectCommand(s3Params));
        const s3Url = `https://${S3_BUCKET_NAME}.s3.${AWS_S3_REGION}.amazonaws.com/${fileKey}`;
        res.json({ url: s3Url });
    } catch (error) {
        console.error("[SME UPLOAD MEDIA] Error uploading to S3:", error);
        res.status(500).json({ message: 'Server error during file upload.' });
    }
});

app.get('/api/hiring/sme-coding-problems', hiringModeratorAuth, async (req, res) => {
    try {
        // Scan the entire table for problems
        // In a production environment with millions of problems,
        // this should be a more optimized query, but for now,
        // Scan is the simplest way to get all problems.
        const { Items } = await docClient.send(new ScanCommand({
            TableName: HIRING_CODING_PROBLEMS_TABLE
            // We don't filter by 'createdBy' here, so the moderator
            // sees problems from *all* SMEs.
        }));
        
        // Optional: Filter out any non-problem items if the table is shared
        const problems = (Items || []).filter(item => item.problemId && item.problemId.startsWith('hire_problem_'));

        res.json(problems);
    } catch (error) {
        console.error("Hiring Mod Get SME Problems Error:", error);
        res.status(500).json({ message: 'Server error fetching SME problem library.' });
    }
});

app.get('/api/hiring/sme-coding-problems', hiringModeratorAuth, async (req, res) => {
    try {
        // Scan the entire table for problems
        // In a production environment with millions of problems,
        // this should be a more optimized query, but for now,
        // Scan is the simplest way to get all problems.
        const { Items } = await docClient.send(new ScanCommand({
            TableName: HIRING_CODING_PROBLEMS_TABLE
            // We don't filter by 'createdBy' here, so the moderator
            // sees problems from *all* SMEs.
        }));
        
        // Optional: Filter out any non-problem items if the table is shared
        const problems = (Items || []).filter(item => item.problemId && item.problemId.startsWith('hire_problem_'));

        res.json(problems);
    } catch (error) {
        console.error("Hiring Mod Get SME Problems Error:", error);
        res.status(500).json({ message: 'Server error fetching SME problem library.' });
    }
});

/**
 * @route   GET /api/hiring/sme-aptitude-tests
 * @desc    Hiring Moderator: Gets ALL aptitude tests from ALL SMEs
 * @access  Private (Hiring Moderator)
 */
app.get('/api/hiring/sme-aptitude-tests', hiringModeratorAuth, async (req, res) => {
    try {
        // Scan the entire table for SME-created aptitude tests
        const { Items } = await docClient.send(new ScanCommand({
            TableName: HIRING_APTITUDE_TESTS_TABLE
            // We don't filter by 'createdBy' here, so the moderator
            // sees tests from *all* SMEs.
        }));
        
        // Optional: Filter out any non-test items if the table is shared
        const tests = (Items || []).filter(item => item.aptitudeTestId && item.aptitudeTestId.startsWith('hire_apt_'));

        res.json(tests);
    } catch (error) {
        console.error("Hiring Mod Get SME Aptitude Tests Error:", error);
        res.status(500).json({ message: 'Server error fetching SME test library.' });
    }
});

app.post('/api/public/request-mock-token', async (req, res) => {
    
    // --- *** 1. Your two Trial Test IDs are pasted here *** ---
    const TRIAL_TEST_IDS = [
        "hire_coding_test_3f083cda-1321-4e21-8955-c91f6611389f",
        "hire_coding_test_7d406351-ecbf-4e92-a886-442dd3e862fa"
    ];
    
    // --- *** 2. SET YOUR VALUES HERE *** ---
    // This is the full URL to the new HTML page you are adding in this step.
    const GET_TOKEN_PAGE_URL = "https://www.testify-lac.com/get-trial-token.html"; 

    // This title is just a fallback in case the DB lookup fails
    const MOCK_TEST_TITLE = "Testify Trial Test";

    const { name, email, mobile, organization, role } = req.body;

    if (!name || !email) {
        return res.status(400).json({ message: 'Name and Email are required.' });
    }

    const emailLower = email.toLowerCase();

    try {
        // --- 1. Randomly select one of your test IDs ---
        const selectedTestId = TRIAL_TEST_IDS[Math.floor(Math.random() * TRIAL_TEST_IDS.length)];
        console.log(`[Mock Token] Selected testId: ${selectedTestId} for user ${emailLower}`);

        // --- 2. Get the selected test's details (to get its type) ---
        let testType = null;
        let testTitle = MOCK_TEST_TITLE;

        // Check if it's a coding test
        const { Item: codingTest } = await docClient.send(new GetCommand({
            TableName: HIRING_CODING_TESTS_TABLE, Key: { codingTestId: selectedTestId }
        }));
        
        if (codingTest) {
            testType = 'coding';
            testTitle = codingTest.title; // Use the real test title
        } else {
            // Check if it's an aptitude test
            const { Item: aptitudeTest } = await docClient.send(new GetCommand({
                TableName: HIRING_APTITUDE_TESTS_TABLE, Key: { aptitudeTestId: selectedTestId }
            }));
            if (aptitudeTest) {
                testType = 'aptitude';
                testTitle = aptitudeTest.title; // Use the real test title
            }
        }

        if (!testType) {
            console.error(`[Mock Token] Could not find test details for selected testId: ${selectedTestId}`);
            return res.status(500).json({ message: "Server error: Could not find trial test details." });
        }

        // --- 3. Dynamically create a new JWT for this specific test ---
        const payload = {
            user: {
                email: 'mock-user@testify.com', // Placeholder email
                testId: selectedTestId,
                assignmentId: `mock_${selectedTestId}_${uuidv4().substring(0, 8)}`, // A generic, but unique-per-request, assignmentId
                testType: testType,
                isMockTest: true, // The most important flag!
                isExternal: true
            }
        };
        // This token is valid for 1 day
        const dynamicallyGeneratedToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' });

        // --- 4. Save the tester's details to the new table ---
        const newTrialUser = {
            email: emailLower, // Primary Key (will overwrite if they re-apply)
            fullName: name,
            mobile: mobile,
            organization: organization,
            role: role,
            requestedAt: new Date().toISOString(),
            lastTestIdSent: selectedTestId // Store which test we sent them
        };

        await docClient.send(new PutCommand({
            TableName: HIRING_TRIAL_USERS_TABLE, // Use the new table
            Item: newTrialUser
        }));
        
        // --- 5. Send the email with the *LINK* to the get-token page ---
        
        // *** THIS IS THE NEW LINK ***
        // It combines your page URL with the unique token
        const tokenLink = `${GET_TOKEN_PAGE_URL}?token=${dynamicallyGeneratedToken}`;

        const mailOptions = {
            to: email,
            subject: `Your Trial Test Link for ${testTitle}`, // Updated subject
            html: `
                <div style="font-family: 'Inter', Arial, sans-serif; background-color: #f9fafb; color: #1f2937; padding: 30px 20px;">
  <div style="max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 12px rgba(79,70,229,0.08);">
    
    <!-- Header / Branding -->
    <div style="background: linear-gradient(90deg, #4F46E5, #7C3AED); padding: 24px 0; text-align: center;">
      <img src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1756037774/Gemini_Generated_Image_eu0ib0eu0ib0eu0i_z0amjh.png" 
           alt="Testify Logo" 
           style="height: 50px; width: auto; border-radius: 8px;">
      <h1 style="color: #ffffff; font-size: 22px; margin-top: 10px; letter-spacing: 0.5px;">Testify Secure Mock Assessment (Beta)</h1>
    </div>

    <!-- Body -->
    <div style="padding: 30px;">
      <h2 style="font-size: 20px; color: #111827;">Hello ${name},</h2>
      <p style="font-size: 15px; color: #374151; margin-top: 10px;">
        🎉 Thank you for joining our <strong>Beta Testing Program</strong>!  
        Your participation helps us enhance transparency and security in online assessments.
      </p>

      <p style="margin-top: 15px; color: #4B5563;">
        Click the button below to access your <strong>unique trial token</strong> and download the 
        <strong>Testify Secure Test Application</strong>.
        <br><em>This link will expire in 24 hours.</em>
      </p>

      <!-- CTA Button -->
      <div style="text-align: center; margin: 30px 0;">
        <a href="${tokenLink}" 
           style="display: inline-block; background: linear-gradient(90deg, #4F46E5, #7C3AED); color: #ffffff; font-weight: 600; text-decoration: none; padding: 14px 28px; border-radius: 8px; font-size: 16px; letter-spacing: 0.3px; box-shadow: 0 4px 10px rgba(79,70,229,0.2);">
          🔑 Get Your Trial Token & Download App
        </a>
      </div>

      <!--<p style="font-size: 14px; color: #6B7280;">-->
      <!--  If the button doesn’t work, copy and paste this URL into your browser:-->
      <!--</p>-->
      <!--<p style="background-color: #f3f4f6; border-left: 3px solid #4F46E5; padding: 10px; border-radius: 5px; font-family: monospace; color: #1f2937; font-size: 13px; word-break: break-all;">-->
      <!--  ${tokenLink}-->
      <!--</p>-->

      <p style="margin-top: 20px; color: #4B5563;">
        Once installed, launch the Testify application, paste your token, and begin your secure mock test.  
        Your feedback will directly help us shape the next generation of **AI-Proctored Assessments**.
      </p>

      <p style="margin-top: 25px; font-size: 15px; color: #111827;">
        Best regards,<br>
        <strong>The Testify Team</strong><br>
        <span style="font-size: 13px; color: #6B7280;">A Xeta Solutions Initiative</span>
      </p>
    </div>

    <!-- Footer -->
    <div style="background-color: #f3f4f6; text-align: center; padding: 16px; font-size: 13px; color: #6B7280;">
      © 2025 Testify • All rights reserved.<br>
      This is a Beta communication from <strong>Xeta Solutions</strong>.
    </div>
  </div>
</div>

            `
        };

        await sendEmailWithSES(mailOptions);

        res.status(200).json({ message: 'Success! Please check your email for the trial test token.' });

    } catch (error) {
        console.error("Request Mock Token Error:", error);
        res.status(500).json({ message: 'Server error processing your request.' });
    }
});
// [REPLACE your old /api/proctoring/join with this]

// [ADD THIS NEW ENDPOINT]
// This is what the moderator dashboard calls to get viewer credentials for *each* student
app.post('/api/proctoring/viewer-credentials', hiringModeratorAuth, async (req, res) => {
    const { channelARN } = req.body;
    const moderatorId = req.user.email; // The moderator's unique ID

    if (!channelARN) {
        return res.status(400).json({ message: 'Channel ARN is required.' });
    }

    console.log(`[KVS Viewer] Moderator ${moderatorId} requests credentials for ${channelARN}`);

    try {
        // 1. Get the Signaling Channel Endpoint
        const endpointResponse = await kinesisVideoClient.send(new GetSignalingChannelEndpointCommand({
            ChannelARN: channelARN,
            SingleMasterChannelEndpointConfiguration: {
                Protocols: ["WSS", "HTTPS"],
                Role: "VIEWER" // The moderator is the VIEWER
            }
        }));

        const wssEndpoint = endpointResponse.ResourceEndpointList.find(ep => ep.Protocol === "WSS").ResourceEndpoint;
        const httpsEndpoint = endpointResponse.ResourceEndpointList.find(ep => ep.Protocol === "HTTPS").ResourceEndpoint;

        // 2. Get ICE Server (TURN) configuration
        const signalingClient = new KinesisVideoSignalingClient({
            region: process.env.AWS_REGION || "ap-south-1",
            endpoint: httpsEndpoint,
            credentials: {
                accessKeyId: 'AKIAT4YSUMZD52BNBCAB', // Your existing key
                secretAccessKey: process.env.CHIME_AWS_SECRET_ACCESS_KEY || 'jCJQY7lfiv1LylIqLpzFl9kz96r4FgLcKL+SueGh' // Your existing secret
            }
        });

        const iceServerResponse = await signalingClient.send(new GetIceServerConfigCommand({
            ChannelARN: channelARN,
            Service: "TURN"
        }));

        const iceServers = iceServerResponse.IceServerList.map(server => ({
            urls: server.Uris,
            username: server.Username,
            credential: server.Password,
        }));

        // 3. Send all this information to the frontend
        res.json({
            role: "VIEWER",
            channelARN: channelARN,
            wssEndpoint: wssEndpoint,
            httpsEndpoint: httpsEndpoint,
            iceServers: iceServers,
            externalUserId: moderatorId
        });

    } catch (error) {
        console.error(`[KVS Viewer] Error getting credentials for ${channelARN}:`, error);
        res.status(500).json({ message: 'Error creating viewer credentials.' });
    }
});
/**
 * @route   POST /api/proctoring/join
 * @desc    Student (MASTER) joins the proctoring session and gets KVS credentials
 * @access  Private (authMiddleware)
 */
app.post('/api/proctoring/join', authMiddleware, async (req, res) => {
    const { testId, role } = req.body;
    const studentEmail = req.user.email;
    const externalUserId = `student_${studentEmail}_${testId}`; // Unique ID for KVS

    if (role !== 'STUDENT') {
        return res.status(400).json({ message: 'Invalid role for this endpoint.' });
    }

    // Create a unique, valid channel name
    const channelName = `proctor_${testId}_${studentEmail.replace(/[^a-zA-Z0-9_.-]/g, '_')}`.substring(0, 256);
    console.log(`[KVS Master] Join request for channel: ${channelName}`);

    try {
        let channelARN;

        // 1. Check if channel exists, if not, create it
        try {
            const describeResponse = await kinesisVideoClient.send(new DescribeSignalingChannelCommand({
                ChannelName: channelName
            }));
            channelARN = describeResponse.ChannelInfo.ChannelARN;
            console.log(`[KVS Master] Found existing channel: ${channelARN}`);
        } catch (error) {
            if (error.name === 'ResourceNotFoundException') {
                console.log(`[KVS Master] Channel not found, creating...`);
                const createResponse = await kinesisVideoClient.send(new CreateSignalingChannelCommand({
                    ChannelName: channelName,
                    ChannelType: 'SINGLE_MASTER' // Student is the single master
                }));
                channelARN = createResponse.ChannelARN;
                console.log(`[KVS Master] Created new channel: ${channelARN}`);
            } else {
                throw error; // Re-throw other errors
            }
        }

        // 2. Get Signaling Channel Endpoints
        const endpointResponse = await kinesisVideoClient.send(new GetSignalingChannelEndpointCommand({
            ChannelARN: channelARN,
            SingleMasterChannelEndpointConfiguration: {
                Protocols: ["WSS", "HTTPS"],
                Role: "MASTER" // Student is the MASTER
            }
        }));

        const wssEndpoint = endpointResponse.ResourceEndpointList.find(ep => ep.Protocol === "WSS").ResourceEndpoint;
        const httpsEndpoint = endpointResponse.ResourceEndpointList.find(ep => ep.Protocol === "HTTPS").ResourceEndpoint;
        
        console.log(`[KVS Master] Got endpoints: WSS: ${wssEndpoint}, HTTPS: ${httpsEndpoint}`);

        // 3. Get ICE Server (TURN) Configuration
        const signalingClient = new KinesisVideoSignalingClient({
            region: process.env.AWS_REGION || "ap-south-1",
            endpoint: httpsEndpoint, // Use the HTTPS endpoint for this client
            credentials: {
                accessKeyId: 'AKIAT4YSUMZD52BNBCAB', // Your existing key
                secretAccessKey: process.env.CHIME_AWS_SECRET_ACCESS_KEY || 'jCJQY7lfiv1LylIqLpzFl9kz96r4FgLcKL+SueGh' // Your existing secret
            }
        });

        const iceServerResponse = await signalingClient.send(new GetIceServerConfigCommand({
            ChannelARN: channelARN,
            Service: "TURN" // Use TURN for NAT traversal
        }));

        const iceServers = iceServerResponse.IceServerList.map(server => ({
            urls: server.Uris,
            username: server.Username,
            credential: server.Password,
        }));
        
        console.log(`[KVS Master] Got ${iceServers.length} ICE servers.`);

        // 4. Send all credentials to the student's frontend
        res.json({
            role: "MASTER",
            channelARN: channelARN,
            wssEndpoint: wssEndpoint,
            httpsEndpoint: httpsEndpoint,
            iceServers: iceServers,
            externalUserId: externalUserId // The unique ID for this student
        });

    } catch (error) {
        console.error(`[KVS Master] Error joining channel ${channelName}:`, error);
        res.status(500).json({ message: 'Error initializing proctoring session.' });
    }
});
app.put('/api/admin/jobs/:jobId', authMiddleware, async (req, res) => {
    // 1. Check for Admin role
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }

    const { jobId } = req.params;
    const { title, location, department, description, applicationDeadline } = req.body;

    // 2. Validate input
    if (!title || !location || !department || !description || !applicationDeadline) {
        return res.status(400).json({ message: 'All job fields, including deadline, are required.' });
    }

    try {
        // 3. Check if the job exists (optional, but good practice)
        const { Item: existingJob } = await docClient.send(new GetCommand({
            TableName: CORRECT_JOBS_TABLE_NAME,
            Key: { jobId: jobId }
        }));

        if (!existingJob) {
            return res.status(404).json({ message: 'Job not found.' });
        }
        
        // 4. Prepare and execute the Update command
        const updateParams = {
            TableName: CORRECT_JOBS_TABLE_NAME,
            Key: { jobId: jobId },
            UpdateExpression: "SET title = :t, #loc = :l, department = :d, description = :desc, applicationDeadline = :ad",
            ExpressionAttributeNames: {
                "#loc": "location" // "location" can be a reserved word
            },
            ExpressionAttributeValues: {
                ":t": title,
                ":l": location,
                ":d": department,
                ":desc": description,
                ":ad": applicationDeadline
            },
            ReturnValues: "UPDATED_NEW" // Return the updated item
        };

        await docClient.send(new UpdateCommand(updateParams));

        res.status(200).json({ message: 'Job updated successfully!' });

    } catch (error) {
        console.error("Update Job Error:", error);
        res.status(500).json({ message: 'Server error updating job.' });
    }
});

/**
 * @route   DELETE /api/admin/jobs/:jobId
 * @desc    Admin: Delete a job opening
 * @access  Private (Admin Only)
 */
app.delete('/api/admin/jobs/:jobId', authMiddleware, async (req, res) => {
    // 1. Check for Admin role
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }

    const { jobId } = req.params;

    try {
        // 2. Execute the Delete command
        await docClient.send(new DeleteCommand({
            TableName: CORRECT_JOBS_TABLE_NAME,
            Key: { jobId: jobId }
        }));

        // Note: You might also want to delete associated applications from "TestifyApplications"
        // (This would require a more complex operation to find and batch-delete them)

        res.status(200).json({ message: 'Job deleted successfully.' });

    } catch (error) {
        console.error("Delete Job Error:", error);
        res.status(500).json({ message: 'Server error deleting job.' });
    }
});


server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
