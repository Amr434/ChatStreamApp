using Application.Common.Model;
using Application.Interfaces;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Text.Json;

namespace Infrastructure.Services
{
    public class EmailService : IEmailService
    {
        private readonly SmtpClient _smtpClient;
        private readonly string _fromEmail;
        public EmailService(IConfiguration configuration)
        {

            _fromEmail = configuration["SmtpSettings:From"];
            
            _smtpClient = new SmtpClient()
            {
                Host = configuration["SmtpSettings:Host"],
                Port = int.Parse(configuration["SmtpSettings:Port"]),
                EnableSsl = bool.Parse(configuration["SmtpSettings:EnableSsl"]),
                Credentials = new NetworkCredential(configuration["SmtpSettings:Username"], configuration["SmtpSettings:Password"]),
                
            };
        }

        public async Task SendEmailAsync(string to, string subject, string body)
        {
            var mailMessage = new MailMessage(_fromEmail, to, subject, body)
            {
                IsBodyHtml = true
            };
            await _smtpClient.SendMailAsync(mailMessage);
        }
    }
}
