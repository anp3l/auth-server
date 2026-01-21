import { EmailService, EmailOptions } from './email.interface';
import { ENABLE_LOGS } from '../../config/env';
import { getTemplateEngine } from './template-engine';

export class MockEmailService implements EmailService {
  async sendEmail(options: EmailOptions): Promise<void> {
    console.log('\n📧 ========== MOCK EMAIL ==========');
    console.log(`To: ${Array.isArray(options.to) ? options.to.join(', ') : options.to}`);
    console.log(`Subject: ${options.subject}`);
    console.log(`From: ${options.from || 'noreply@yourapp.com'}`);
    console.log('\n--- HTML Content (first 500 chars) ---');
    console.log(options.html.substring(0, 500) + '...');
    console.log('==================================\n');
    
    if (ENABLE_LOGS) {
      console.log('✅ Mock email sent successfully');
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
