import mongoose from 'mongoose';
import { MONGO_URI } from './config/env';

const uri: string = MONGO_URI;

const mongoConnection = mongoose.connect(uri);

export default mongoConnection;