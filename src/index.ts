import './config/env';
import { PORT, NODE_ENV, ENABLE_LOGS, ALLOWED_ORIGINS } from './config/env';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import mongoConnection from './mongo-connection';
import authRoutes from './routes/auth.routes';
import adminRoutes from './routes/admin.routes';
import swaggerUi from 'swagger-ui-express';
import swaggerJsDoc from 'swagger-jsdoc';
import { version } from '../package.json';
import { apiLimiter } from './middleware/rateLimiter.middleware';
import { startCleanupScheduler } from './tasks/cleanup.task';

const app = express();
const port = PORT;

// === SWAGGER CONFIG ===
const swaggerOptions = {
  swaggerDefinition: {
    openapi: '3.0.0',
    info: {
      title: 'Auth Server API',
      version: version,
      description: 'Production-ready Identity Provider API with JWT authentication, refresh tokens, and RBAC. Supports RS256 signed tokens for secure microservices communication.'
    },
    servers: [
      {
        url: `http://localhost:${port}`,
        description: 'Development server'
      },
      {
        url: 'https://your-production-domain.com',
        description: 'Production server'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Enter your JWT access token in the format: Bearer {token}'
        }
      }
    },
    tags: [
      {
        name: 'Auth',
        description: 'Authentication endpoints (Login, Signup, Token management)'
      },
      {
        name: 'User',
        description: 'User profile management endpoints'
      },
      {
        name: 'Admin',
        description: 'Admin endpoints for user management (Admin role required)'
      },
      {
        name: 'Health',
        description: 'Service health and status endpoints'
      }
    ]
  },
  apis: [
    './src/routes/*.ts',
    './src/routes/**/*.ts',
    './src/index.ts'
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

// === SECURITY MIDDLEWARE ===

// Helmet: vulnarability protection
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "validator.swagger.io"]
    }
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// CORS configuration
const corsOptions = {
  origin: NODE_ENV === 'production' 
    ? ALLOWED_ORIGINS
    : '*',
  credentials: true,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Body parser
app.use(express.json({ limit: '10mb' })); // playload limit
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.set('trust proxy', 1);

// === LOGGING MIDDLEWARE ===
if (ENABLE_LOGS) {
  app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
      const duration = Date.now() - start;
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
    });
    next();
  });
}

// === RATE LIMITING ===
app.use('/auth', apiLimiter);

// === SWAGGER UI ===
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs, {
  explorer: true,
  customSiteTitle: "Auth Server API Docs",
  customCss: '.swagger-ui .topbar { display: none }',
  swaggerOptions: {
    persistAuthorization: true
  }
}));

// === DB CONNECTION ===
mongoConnection.then(() => {
  console.log('✅ Connected to MongoDB');

  startCleanupScheduler();
}).catch((err) => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// === ROUTES ===
app.use('/auth', authRoutes);
app.use('/admin', adminRoutes);

// === HEALTH CHECK ===
/**
 * @swagger
 * /health:
 *   get:
 *     summary: Health check endpoint
 *     description: Returns service status, version, and timestamp. Used for monitoring and load balancer health checks.
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: Service is healthy
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: healthy
 *                 service:
 *                   type: string
 *                   example: auth-server
 *                 version:
 *                   type: string
 *                   example: 0.1.0
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                 uptime:
 *                   type: number
 *                   description: Server uptime in seconds
 *                 environment:
 *                   type: string
 *                   example: development
 */
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    service: 'auth-server',
    version: version,
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: NODE_ENV
  });
});

// === 404 HANDLER ===
app.use((req, res, next) => {
  res.status(404).json({
    error: 'Not Found',
    message: `Route ${req.method} ${req.originalUrl} not found`,
    availableEndpoints: {
      health: '/health',
      docs: '/api-docs',
      auth: '/auth/*'
    }
  });
});

// === GLOBAL ERROR HANDLER ===
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('=== GLOBAL ERROR HANDLER ===');
  console.error('URL:', req.method, req.url);
  console.error('Error:', err);
  console.error('Message:', err.message);
  if (ENABLE_LOGS) {
    console.error('Stack:', err.stack);
  }
  console.error('============================');
  
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
    ...(NODE_ENV === 'development' && { 
      stack: err.stack,
      details: err 
    })
  });
});

// === GRACEFUL SHUTDOWN ===
const gracefulShutdown = (signal: string) => {
  console.log(`\n${signal} received. Starting graceful shutdown...`);
  
  server.close(() => {
    console.log('✅ HTTP server closed');
    
    mongoConnection.then(connection => {
      return connection.disconnect();
    }).then(() => {
      console.log('✅ MongoDB connection closed');
      process.exit(0);
    }).catch(err => {
      console.error('❌ Error during shutdown:', err);
      process.exit(1);
    });
  });
  
  setTimeout(() => {
    console.error('⚠️  Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
};

// === START SERVER ===
const server = app.listen(port, () => {
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log(`║🔐 Auth Server v${version.padEnd(42)}    ║`);
  console.log('╠══════════════════════════════════════════════════════════════╣');
  console.log(`║ Environment: ${NODE_ENV.padEnd(44)}    ║`);
  console.log(`║ Port: ${port!.toString().padEnd(51)}    ║`);
  console.log(`║ Logging: ${(ENABLE_LOGS ? 'enabled' : 'disabled').padEnd(47)}     ║`);
  console.log(`║ Docs: http://localhost:${port}/api-docs${' '.repeat(24)} ║`);
  console.log(`║ Health: http://localhost:${port}/health${' '.repeat(23)}  ║`);
  console.log('╚══════════════════════════════════════════════════════════════╝');
});

// Listen for termination signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));