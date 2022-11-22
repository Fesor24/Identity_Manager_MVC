using MailKit;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace IdentityManagerMVC.Services
{
    //I did try using this method to send maild but it seems
    //google has restricted access to third parties, untrusted probably
    //i will leave it here anyways for future modifications

    public class MailSender : IMailSender
    {
        private readonly ILogger<MailSender> _logger;

        public MailSender(ILogger<MailSender> logger)
        {
            _logger = logger;
        }
        public void SendMail(string address, string subject, string messageBody)
        {
            MimeMessage message = new MimeMessage();

            message.From.Add(new MailboxAddress("IdentityManager", "savion26@ethereal.email"));

            message.To.Add(MailboxAddress.Parse(address));

            message.Subject = subject;

            message.Body = new TextPart("html")
            {
                Text = messageBody
            };

            string emailAddress = "savion26@ethereal.email";
            string password = "QHKQMwfjCtzs4zKSYz";

            SmtpClient client = new SmtpClient();

            try
            {
                client.Connect("smtp.ethereal.email", 587, SecureSocketOptions.StartTls);
                client.Authenticate(emailAddress, password);
                client.Send(message);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error occured in the {nameof(SendMail)} method", ex);
                throw;
            }
            finally
            {
                client.Disconnect(true);
                client.Dispose();
            }
        }
    }
}
