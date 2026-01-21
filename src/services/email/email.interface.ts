export interface EmailOptions {
  to: string | string[];
  subject: string;
  html: string;
  text?: string;
  from?: string;
}

export interface EmailService {
  sendEmail(options: EmailOptions): Promise<void>;
  sendPasswordResetEmail(to: string, resetToken: string, userName: string): Promise<void>;
  sendWelcomeEmail(to: string, userName: string): Promise<void>;
}
