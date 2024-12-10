//<!--===============================================================================================-->
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const PORT = 3000;
//<!--===============================================================================================-->
const app = express();
const corsOptions = require('./cors');
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
//<!--===============================================================================================-->
const server = http.createServer(app);
const io = new Server(server, { cors: corsOptions });
app.use((req, res, next) => {
    req.io = io;
    next();
});
io.on('connection', (socket) => {
    console.log(`${socket.id} connected`);
    socket.on('disconnect', () => {
        console.log(`${socket.id} disconnected`);
    });
});
//<!--===============================================================================================-->
app.use('/user', require('./routes/userRoutes'));
//<!--===============================================================================================-->
const db = require('./models');
db.sequelize.authenticate()
    .then(() => {
        console.log('DB CONNECTED')
        server.listen(PORT, () => {
            console.log(`YOUR PORT IS: ${PORT}`)
        })
    })
    .catch((err) => {
        console.log('DB NOT CONNECTED')
        console.log(err)
    })
//<!--===============================================================================================-->
