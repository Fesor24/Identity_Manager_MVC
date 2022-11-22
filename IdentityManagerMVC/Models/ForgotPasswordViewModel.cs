using System.ComponentModel.DataAnnotations;

namespace IdentityManagerMVC.Models
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress(ErrorMessage = "Please enter a valid email address")]
        public string Email { get; set; } = string.Empty;
    }
}
