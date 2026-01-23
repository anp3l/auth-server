import { EmailService } from './email.interface';
import { MockEmailService } from './mock-email.service';

export type EmailProvider = 'mock' | 'nodemailer' | 'resend';

export function createEmailService(): EmailService {
  const provider = (process.env.EMAIL_PROVIDER || 'mock') as EmailProvider;

  console.log(`📧 Email Service: ${provider}`);

  switch (provider) {
    case 'mock':
    default:
      return new MockEmailService();
  }
}

// Singleton instance
let emailServiceInstance: EmailService | null = null;

export function getEmailService(): EmailService {
  if (!emailServiceInstance) {
    emailServiceInstance = createEmailService();
  }
  return emailServiceInstance;
}
