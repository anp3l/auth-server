import './config/env';
import { PORT, NODE_ENV } from './config/env';
import express from 'express';
import cors from 'cors';
import mongoConnection from './mongo-connection';
import authRoutes from './routes/auth.routes';
import swaggerUi from 'swagger-ui-express';
import swaggerJsDoc from 'swagger-jsdoc';
import { version } from '../package.json';

const app = express();
const port = PORT;

// === SWAGGER CONFIG ===
const swaggerOptions = {
  swaggerDefinition: {
    openapi: '3.0.0',
    info: {
      title: 'Auth Server API',
      version: version,
      description: 'Identity Provider API for User Management and Authentication (RSA signed tokens)'
    },
    servers: [
      {
        url: 'http://localhost:' + port
      }
    ],
    tags: [
      {
        name: 'Auth',
        description: 'Authentication endpoints (Login, Signup)'
      }
    ]
  },
  apis: [
    './src/routes/*.ts',
    './src/routes/**/*.ts'
  ]
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);

// === PROCESS ERROR HANDLERS ===
process.on('unhandledRejection', (reason, promise) => {
  console.error('=== UNHANDLED REJECTION ===');
  console.error('Reason:', reason);
  console.error('Promise:', promise);
  console.error('===========================');
});

process.on('uncaughtException', (error) => {
  console.error('=== UNCAUGHT EXCEPTION ===');
  console.error('Error:', error);
  console.error('Stack:', error.stack);
  console.error('==========================');
  process.exit(1);
});

// === MIDDLEWARE ===
app.use(cors());
app.use(express.json());

// === SWAGGER UI ===
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs, {
  explorer: true,
  customSiteTitle: "Auth Server API Docs"
}));

// === DB CONNECTION ===
mongoConnection.then(() => {
  console.log('Connected to MongoDB');
}).catch((err) => {
  console.error('MongoDB connection error:', err);
});

// === ROUTES ===
app.use('/auth', authRoutes);

// === GLOBAL ERROR HANDLER ===
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('=== GLOBAL ERROR HANDLER ===');
  console.error('URL:', req.method, req.url);
  console.error('Error:', err);
  console.error('Message:', err.message);
  console.error('Stack:', err.stack);
  console.error('============================');
  
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
    details: NODE_ENV === 'development' ? err.stack : undefined
  });
});

// === HEALTH CHECK ===
app.get('/health', (req, res) => {
  res.json({ status: 'Auth Server is running', timestamp: new Date() });
});

// === START SERVER ===
app.listen(port, () => {
  console.log(`🔐 Auth Server running on port ${port} (v${version})`);
  console.log(`📄 Swagger Docs available at http://localhost:${port}/api-docs`);
});