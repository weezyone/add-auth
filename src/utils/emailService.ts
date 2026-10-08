/**
 * Email Service
 * Handles email sending for password reset notifications and other system emails
 */

import * as nodemailer from 'nodemailer';
import { logger } from './logger';
import { appConfig } from '../config';

/**
 * Email configuration interface
 */
export interface EmailConfig {
  host: string;
  port: number;
  secure: boolean;
  auth: {
    user: string;
    pass: string;
  };
  from: string;
  replyTo?: string;
}

/**
 * Email template interface
 */
export interface EmailTemplate {
  subject: string;
  html: string;
  text: string;
}

/**
 * Email options interface
 */
export interface EmailOptions {
  to: string;
  subject: string;
  html?: string;
  text?: string;
  from?: string;
  replyTo?: string;
  attachments?: any[];
}

/**
 * Verification email template. Exported so the mail-transport layer can use it
 * without constructing an SMTP-backed EmailService.
 */
export function buildVerificationEmail(verificationUrl: string, expiresInHours: number): EmailTemplate {
  const subject = 'Email Verification Required';
  
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>${subject}</title>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #007bff; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f8f9fa; }
        .button { display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Email Verification</h1>
        </div>
        <div class="content">
          <h2>Verify Your Email Address</h2>
          <p>Please click the button below to verify your email address:</p>
          <a href="${verificationUrl}" class="button">Verify Email</a>
          <p>If the button doesn't work, copy and paste this link into your browser:</p>
          <p><a href="${verificationUrl}">${verificationUrl}</a></p>
          <p>This link will expire in ${expiresInHours} hours.</p>
        </div>
        <div class="footer">
          <p>This is an automated message. Please do not reply to this email.</p>
          <p>&copy; 2024 Add-Auth. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
  `;

  const text = `
Email Verification

Please use the following link to verify your email address:

${verificationUrl}

This link will expire in ${expiresInHours} hours.

This is an automated message. Please do not reply to this email.
  `;

  return { subject, html, text };
}

/**
 * Email Service Class
 */
export class EmailService {
  private transporter!: nodemailer.Transporter;
  private config: EmailConfig;
  private isConfigured: boolean = false;

  constructor(config?: Partial<EmailConfig>) {
    this.config = {
      host: process.env.EMAIL_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.EMAIL_PORT || '587'),
      secure: process.env.EMAIL_SECURE === 'true',
      auth: {
        user: process.env.EMAIL_USER || '',
        pass: process.env.EMAIL_PASS || ''
      },
      from: process.env.EMAIL_FROM || 'noreply@add-auth.com',
      replyTo: process.env.EMAIL_REPLY_TO || '',
      ...config
    };

    this.initialize();
  }

  /**
   * Initialize email service
   */
  private initialize(): void {
    try {
      // Check if email credentials are configured
      if (!this.config.auth.user || !this.config.auth.pass) {
        logger.warn('Email service not configured - missing credentials');
        return;
      }

      this.transporter = nodemailer.createTransport({
        host: this.config.host,
        port: this.config.port,
        secure: this.config.secure,
        auth: this.config.auth,
        tls: {
          rejectUnauthorized: false
        }
      });

      this.isConfigured = true;
      logger.info('Email service initialized', {
        host: this.config.host,
        port: this.config.port,
        secure: this.config.secure,
        user: this.config.auth.user
      });
    } catch (error) {
      logger.error('Failed to initialize email service:', error);
      this.isConfigured = false;
    }
  }

  /**
   * Test email connection
   */
  async testConnection(): Promise<boolean> {
    if (!this.isConfigured) {
      logger.warn('Email service not configured');
      return false;
    }

    try {
      await this.transporter.verify();
      logger.info('Email service connection test successful');
      return true;
    } catch (error) {
      logger.error('Email service connection test failed:', error);
      return false;
    }
  }

  /**
   * Send email
   */
  async sendEmail(options: EmailOptions): Promise<boolean> {
    if (!this.isConfigured) {
      logger.warn('Email service not configured - cannot send email');
      return false;
    }

    try {
      const emailOptions = {
        from: options.from || this.config.from,
        to: options.to,
        subject: options.subject,
        html: options.html,
        text: options.text,
        replyTo: options.replyTo || this.config.replyTo,
        attachments: options.attachments || []
      };

      const info = await this.transporter.sendMail(emailOptions);
      
      logger.info('Email sent successfully', {
        to: options.to,
        subject: options.subject,
        messageId: info.messageId
      });

      return true;
    } catch (error) {
      logger.error('Failed to send email:', error);
      return false;
    }
  }

  /**
   * Send password reset email
   */
  async sendPasswordResetEmail(email: string, resetToken: string, expiresAt: Date): Promise<boolean> {
    const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;
    const expirationTime = new Date(expiresAt).toLocaleString();

    const template = this.getPasswordResetTemplate(resetUrl, expirationTime);

    return this.sendEmail({
      to: email,
      subject: template.subject,
      html: template.html,
      text: template.text
    });
  }

  /**
   * Send password reset confirmation email
   */
  async sendPasswordResetConfirmationEmail(email: string): Promise<boolean> {
    const template = this.getPasswordResetConfirmationTemplate();

    return this.sendEmail({
      to: email,
      subject: template.subject,
      html: template.html,
      text: template.text
    });
  }

  /**
   * Send account registration email
   */
  async sendRegistrationEmail(email: string, username: string): Promise<boolean> {
    const template = this.getRegistrationTemplate(username);

    return this.sendEmail({
      to: email,
      subject: template.subject,
      html: template.html,
      text: template.text
    });
  }

  /**
   * Send account verification email
   */
  async sendVerificationEmail(email: string, verificationToken: string): Promise<boolean> {
    const verificationUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email?token=${verificationToken}`;
    const template = this.getVerificationTemplate(verificationUrl);

    return this.sendEmail({
      to: email,
      subject: template.subject,
      html: template.html,
      text: template.text
    });
  }

  /**
   * Send security alert email
   */
  async sendSecurityAlertEmail(email: string, alertType: string, details: any): Promise<boolean> {
    const template = this.getSecurityAlertTemplate(alertType, details);

    return this.sendEmail({
      to: email,
      subject: template.subject,
      html: template.html,
      text: template.text
    });
  }

  /**
   * Get password reset email template
   */
  private getPasswordResetTemplate(resetUrl: string, expirationTime: string): EmailTemplate {
    const subject = 'Password Reset Request';
    
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>${subject}</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background-color: #007bff; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background-color: #f8f9fa; }
          .button { display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
          .warning { color: #dc3545; font-weight: bold; }
          .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Password Reset Request</h1>
          </div>
          <div class="content">
            <h2>Reset Your Password</h2>
            <p>We received a request to reset your password. If you made this request, click the button below to reset your password:</p>
            <a href="${resetUrl}" class="button">Reset Password</a>
            <p>If the button doesn't work, copy and paste this link into your browser:</p>
            <p><a href="${resetUrl}">${resetUrl}</a></p>
            <p class="warning">This link will expire on ${expirationTime}</p>
            <p>If you didn't request a password reset, please ignore this email or contact support if you have concerns.</p>
            <p>For security reasons, this link can only be used once.</p>
          </div>
          <div class="footer">
            <p>This is an automated message. Please do not reply to this email.</p>
            <p>&copy; 2024 Add-Auth. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
Password Reset Request

We received a request to reset your password. If you made this request, use the following link to reset your password:

${resetUrl}

This link will expire on ${expirationTime}

If you didn't request a password reset, please ignore this email or contact support if you have concerns.

For security reasons, this link can only be used once.

This is an automated message. Please do not reply to this email.
    `;

    return { subject, html, text };
  }

  /**
   * Get password reset confirmation template
   */
  private getPasswordResetConfirmationTemplate(): EmailTemplate {
    const subject = 'Password Reset Successful';
    
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>${subject}</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background-color: #28a745; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background-color: #f8f9fa; }
          .success { color: #28a745; font-weight: bold; }
          .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Password Reset Successful</h1>
          </div>
          <div class="content">
            <h2>Your password has been reset</h2>
            <p class="success">Your password has been successfully reset.</p>
            <p>You can now log in with your new password.</p>
            <p>If you didn't make this change, please contact support immediately.</p>
          </div>
          <div class="footer">
            <p>This is an automated message. Please do not reply to this email.</p>
            <p>&copy; 2024 Add-Auth. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
Password Reset Successful

Your password has been successfully reset.

You can now log in with your new password.

If you didn't make this change, please contact support immediately.

This is an automated message. Please do not reply to this email.
    `;

    return { subject, html, text };
  }

  /**
   * Get registration email template
   */
  private getRegistrationTemplate(username: string): EmailTemplate {
    const subject = 'Welcome to Add-Auth!';
    
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>${subject}</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background-color: #007bff; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background-color: #f8f9fa; }
          .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Welcome to Add-Auth!</h1>
          </div>
          <div class="content">
            <h2>Hello ${username}!</h2>
            <p>Thank you for registering with Add-Auth. Your account has been successfully created.</p>
            <p>You can now log in and start using our services.</p>
            <p>If you have any questions, please don't hesitate to contact our support team.</p>
          </div>
          <div class="footer">
            <p>This is an automated message. Please do not reply to this email.</p>
            <p>&copy; 2024 Add-Auth. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
Welcome to Add-Auth!

Hello ${username}!

Thank you for registering with Add-Auth. Your account has been successfully created.

You can now log in and start using our services.

If you have any questions, please don't hesitate to contact our support team.

This is an automated message. Please do not reply to this email.
    `;

    return { subject, html, text };
  }

  /**
   * Get verification email template
   */
  private getVerificationTemplate(verificationUrl: string): EmailTemplate {
    return buildVerificationEmail(verificationUrl, 24);
  }

  /**
   * Get security alert email template
   */
  private getSecurityAlertTemplate(alertType: string, details: any): EmailTemplate {
    const subject = `Security Alert: ${alertType}`;
    
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>${subject}</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background-color: #dc3545; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background-color: #f8f9fa; }
          .alert { color: #dc3545; font-weight: bold; }
          .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Security Alert</h1>
          </div>
          <div class="content">
            <h2 class="alert">${alertType}</h2>
            <p>We detected suspicious activity on your account:</p>
            <ul>
              ${Object.entries(details).map(([key, value]) => `<li><strong>${key}:</strong> ${value}</li>`).join('')}
            </ul>
            <p>If this was you, you can safely ignore this email.</p>
            <p>If you didn't authorize this activity, please contact support immediately.</p>
          </div>
          <div class="footer">
            <p>This is an automated message. Please do not reply to this email.</p>
            <p>&copy; 2024 Add-Auth. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
Security Alert: ${alertType}

We detected suspicious activity on your account:

${Object.entries(details).map(([key, value]) => `${key}: ${value}`).join('\n')}

If this was you, you can safely ignore this email.

If you didn't authorize this activity, please contact support immediately.

This is an automated message. Please do not reply to this email.
    `;

    return { subject, html, text };
  }
}

// Export default instance
export const emailService = new EmailService();

export default emailService;