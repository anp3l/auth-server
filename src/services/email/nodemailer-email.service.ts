import nodemailer, { Transporter } from 'nodemailer';
import { EmailService, EmailOptions } from './email.interface';
import { getTemplateEngine } from './template-engine';

export class NodemailerEmailService implements EmailService {
  private transporter: Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
  }

  async sendEmail(options: EmailOptions): Promise<void> {
    try {
      await this.transporter.sendMail({
        from: options.from || process.env.EMAIL_FROM || 'noreply@yourapp.com',
        to: Array.isArray(options.to) ? options.to.join(', ') : options.to,
        subject: options.subject,
        html: options.html,
        text: options.text
      });
      
      console.log(`✅ Email sent to ${options.to}`);
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
