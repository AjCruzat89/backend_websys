const corsOptions = {
    origin: ['http://localhost:5173', 'http://localhost:5174', 'http://192.168.1.10:5173'],
    methods: ['*'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
    credentials: true
}

module.exports = corsOptions