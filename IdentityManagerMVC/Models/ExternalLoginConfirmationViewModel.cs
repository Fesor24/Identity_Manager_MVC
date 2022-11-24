using System.ComponentModel.DataAnnotations;

namespace IdentityManagerMVC.Models
{
    public class ExternalLoginConfirmationViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
    }
}
