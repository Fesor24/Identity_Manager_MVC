namespace IdentityManagerMVC.Services
{
    public interface IMailSender
    {
        void SendMail(string address, string subject, string messageBody);
    }
}