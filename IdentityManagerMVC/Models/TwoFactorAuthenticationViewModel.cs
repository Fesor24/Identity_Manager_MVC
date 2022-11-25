namespace IdentityManagerMVC.Models
{
    public class TwoFactorAuthenticationViewModel
    {
        public string Code { get; set; } = string.Empty;
        public string Token { get; set; } = string.Empty;
    }
}
