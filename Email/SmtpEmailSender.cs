using Microsoft.AspNetCore.Identity.UI.Services;
using System.Net;
using System.Net.Mail;

public class SmtpEmailSender : IEmailSender
{
    private readonly IConfiguration _configuration;

    public SmtpEmailSender(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public async Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        var smtpSection = _configuration.GetSection("Email:Smtp");
        var host = smtpSection["Host"];
        var port = int.Parse(smtpSection["Port"]);
        var enableSsl = bool.Parse(smtpSection["EnableSsl"]);
        var user = smtpSection["User"];
        var password = smtpSection["Password"];
        var sender = smtpSection["Sender"];

        using var client = new SmtpClient(host, port)
        {
            Credentials = new NetworkCredential(user, password),
            EnableSsl = enableSsl
        };

        var mail = new MailMessage
        {
            From = new MailAddress(sender),
            Subject = subject,
            Body = htmlMessage,
            IsBodyHtml = true
        };
        mail.To.Add(email);

        await client.SendMailAsync(mail);
    }
}
