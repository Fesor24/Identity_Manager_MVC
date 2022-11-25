using Microsoft.AspNetCore.Mvc.Rendering;
using System.ComponentModel.DataAnnotations;

namespace IdentityManagerMVC.Models
{
    public class RegisterViewModel
    {
        [Required(ErrorMessage ="Email Address is a required field")]
        [EmailAddress]
        [Display(Name = "Email Address")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is a required field")]
        [DataType(DataType.Password)]
        [StringLength(50, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 7)]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage ="Confirm Password is a required field")]
        [Compare("Password", ErrorMessage ="Password and Confirm Password do not match")]
        [DataType(DataType.Password)]
        [Display(Name ="Confirm Password")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required(ErrorMessage ="Please include your name")]
        public string Name { get; set; } = string.Empty;

        public IEnumerable<SelectListItem>? RoleList { get; set; }

        public string RoleSelected { get; set; } = string.Empty;
    }
}
