import { Resend } from 'resend';
import { EmailService, EmailOptions } from './email.interface';
import { getTemplateEngine } from './template-engine';

export class ResendEmailService implements EmailService {
  private resend: Resend;

  constructor() {
    const apiKey = process.env.RESEND_API_KEY;
    if (!apiKey) {
      throw new Error('RESEND_API_KEY is required');
    }
    this.resend = new Resend(apiKey);
  }

  async sendEmail(options: EmailOptions): Promise<void> {
    try {
      const { data, error } = await this.resend.emails.send({
        from: options.from || process.env.EMAIL_FROM || 'noreply@yourapp.com',
        to: Array.isArray(options.to) ? options.to : [options.to],
        subject: options.subject,
        html: options.html,
        text: options.text
      });

      if (error) {
        console.error('❌ Resend error:', error);
        throw new Error('Failed to send email via Resend');
      }

      console.log(`✅ Email sent via Resend (ID: ${data?.id})`);
    } catch (error) {
      console.error('❌ Email send failed:', error);
      throw new Error('Failed to send email');
    }
  }

  async sendPasswordResetEmail(to: string, resetToken: string, userName: string): Promise<void> {
    const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:4200'}/reset-password?token=${resetToken}`;
    
    const templateEngine = getTemplateEngine();
    const html = templateEngine.compile('password-reset', {
      userName,
      resetUrl,
      expiryHours: 1,
      appName: process.env.APP_NAME || 'Manga TCG Store',
      supportEmail: process.env.SUPPORT_EMAIL || 'support@yourapp.com'
    });

    await this.sendEmail({
      to,
      subject: 'Password Reset Request',
      html,
      text: `Reset your password: ${resetUrl}`
    });
  }

    async sendWelcomeEmail(to: string, userName: string): Promise<void> {
    const shopUrl = process.env.FRONTEND_URL || 'http://localhost:4200';
    
    const templateEngine = getTemplateEngine();
    const html = templateEngine.compile('welcome', {
      userName,
      shopUrl,
      appName: process.env.APP_NAME || 'Manga TCG Store',
      supportEmail: process.env.SUPPORT_EMAIL || 'support@yourapp.com',
      year: new Date().getFullYear()
    });

    await this.sendEmail({
      to,
      subject: `Welcome to ${process.env.APP_NAME || 'Manga TCG Store'}!`,
      html
    });
  }
}
