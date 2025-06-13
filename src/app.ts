import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import swaggerUi from 'swagger-ui-express';
import swaggerDocument from './docs/swagger.json';
import authRoutes from './routes/authRoutes';

const app = express();

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.use(helmet());
app.use(cors());
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/api/auth', authRoutes);

app.get("/health", (req, res) => {
  res.json({ status: "OK" });
});

// Example test route
app.get('/', (_req:any, res: any) => {
  res.send('API is running...');
});

export default app;
