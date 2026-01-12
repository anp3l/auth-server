import { Schema, model } from 'mongoose';

const userSchema = new Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true,
    minlength: 3
  },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    lowercase: true
  },
  password: { 
    type: String, 
    required: true,
    minlength: 6
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
});

export const User = model('User', userSchema);