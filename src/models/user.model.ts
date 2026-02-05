import { Schema, model, Document, Types } from 'mongoose';

export interface IUser extends Document {
  firstName?: string;
  lastName?: string;
  dateOfBirth?: Date;
  gender?: 'male' | 'female' | 'other';
  bio?: string;
  email: string;
  emailPreferences?: {
    newsletter: boolean;
    notifications: boolean;
    language: string;
    currency: string;
  };
  username: string;
  password: string;
  role: 'customer' | 'admin';
  avatar?: string;
  phone?: string;
  addresses?: Array<{
    type: 'shipping' | 'billing' | 'both';
    firstName: string;
    lastName: string;
    company?: string;
    addressLine1: string;
    addressLine2?: string;
    city: string;
    state: string;
    postalCode: string;
    country: string;
    phone: string;
    isDefault: boolean;
  }>;
  defaultAddressId?: Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
  isActive: boolean;
  lastLogin?: Date;
  isBanned?: boolean;
  banReason?: string;
  
  setDefaultAddress(addressId: string): Promise<this>;
  fullName: string;  // Virtual
}

const userSchema = new Schema<IUser>({
  username: { 
    $type: String, 
    required: true, 
    unique: true,
    minlength: 3,
    maxlength: 30,
    trim: true,
    match: [/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers and underscores']
  },
  email: { 
    $type: String, 
    required: true, 
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Invalid email format']
  },
  password: { 
    $type: String, 
    required: true,
    minlength: 8
  },
  role: {
    $type: String,
    enum: ['customer', 'admin'],
    default: 'customer',
    required: true
  },
  firstName: {
    $type: String,
    trim: true,
    maxlength: 50
  },
  lastName: {
    $type: String,
    trim: true,
    maxlength: 50
  },
  avatar: { 
    $type: String 
  },
  phone: { 
    $type: String,
    match: [/^\+?[1-9]\d{1,14}$/, 'Invalid phone number format']
  },
  dateOfBirth: { 
    $type: Date 
  },
  gender: { 
    $type: String, 
    enum: ['male', 'female', 'other'] 
  },
  bio: { 
    $type: String, 
    maxlength: 500 
  },
  isActive: { 
    $type: Boolean, 
    default: true 
  },
  lastLogin: { 
    $type: Date 
  },
  isBanned: { 
    $type: Boolean,
    default: false
  },
  banReason: { 
    $type: String 
  },
  addresses: [{
    type: { 
      $type: String, 
      enum: ['shipping', 'billing', 'both'], 
      default: 'shipping' 
    },
    firstName: { 
      $type: String
    },
    lastName: { 
      $type: String
    },
    company: { 
      $type: String 
    },
    addressLine1: { 
      $type: String
    },
    addressLine2: { 
      $type: String 
    },
    city: { 
      $type: String
    },
    state: { 
      $type: String
    },
    postalCode: { 
      $type: String
    },
    country: { 
      $type: String
    },
    phone: { 
      $type: String
    }, 
    isDefault: { 
      $type: Boolean, 
      default: false 
    }
  }],
  defaultAddressId: { 
    $type: Schema.Types.ObjectId
  },
  emailPreferences: {
    newsletter: { 
      $type: Boolean, 
      default: false 
    },
    notifications: { 
      $type: Boolean, 
      default: true 
    },
    language: { 
      $type: String, 
      default: 'it',
      enum: ['it', 'en', 'es', 'fr', 'de']
    },
    currency: { 
      $type: String, 
      default: 'EUR',
      enum: ['EUR', 'USD', 'GBP']
    }
  },
  createdAt: { 
    $type: Date, 
    default: Date.now 
  },
  updatedAt: {
    $type: Date,
    default: Date.now
  }
}, {
  timestamps: true,
  typeKey: '$type',
  toJSON: {
    virtuals: true,
    transform: function(_doc: any, ret: any) {
      ret.id = ret._id.toString();
      delete ret._id;
      delete ret.__v;
      delete ret.password;
      
      if (ret.addresses && Array.isArray(ret.addresses)) {
        ret.addresses = ret.addresses.map((addr: any) => {
          const address = { ...addr };
          if (address._id) {
            address.id = address._id.toString();
            delete address._id;
          }
          return address;
        });
      }
      
      return ret;
    }
  }
});

userSchema.virtual('fullName').get(function(this: IUser) {
  if (this.firstName && this.lastName) {
    return `${this.firstName} ${this.lastName}`;
  }
  return this.username;
});

userSchema.methods.setDefaultAddress = async function(addressId: string) {
  if (this.addresses) {
    this.addresses.forEach((addr: any) => {
      addr.isDefault = false;
    });
    
    const address = this.addresses.find((a: any) => a._id.toString() === addressId);
    if (address) {
      address.isDefault = true;
      this.defaultAddressId = new Types.ObjectId(addressId);
    }
  }
  return this.save();
};

userSchema.index({ email: 1 });
userSchema.index({ username: 1 });
userSchema.index({ role: 1 });
userSchema.index({ isActive: 1, isBanned: 1 });

export const User = model<IUser>('User', userSchema);
