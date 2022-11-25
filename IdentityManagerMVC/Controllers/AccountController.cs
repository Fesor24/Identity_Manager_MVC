using IdentityManagerMVC.Models;
using IdentityManagerMVC.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Security.Claims;

namespace IdentityManagerMVC.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IMailSender _mailSender;

        public AccountController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<IdentityUser> signInManager,
            IMailSender mailsender)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _mailSender = mailsender;
        }
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Register(string? returnUrl = null)
        {
            if(!await _roleManager.RoleExistsAsync("Admin"))
            {
                //typically we create roles by seeding the data but lets do it different here
                await _roleManager.CreateAsync(new IdentityRole("Admin"));
                await _roleManager.CreateAsync(new IdentityRole("User"));
            }

            List<SelectListItem> listItems = new List<SelectListItem>();

            listItems.Add(new SelectListItem
            {
                Value = "Admin",
                Text = "Admin"
            });

            listItems.Add(new SelectListItem
            {
                Value = "User",
                Text = "User"
            });

            ViewData["ReturnUrl"] = returnUrl;
            RegisterViewModel rvm = new RegisterViewModel()
            {
                RoleList = listItems
            };

            return View(rvm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> Register(RegisterViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            returnUrl = returnUrl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var user = new AppUser()
                {
                    Email = model.Email,
                    UserName = model.Email,
                    Name = model.Name
                };

                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    if(model.RoleSelected is not null && model.RoleSelected.Length > 0 && model.RoleSelected is "Admin")
                    {
                        await _userManager.AddToRoleAsync(user, "Admin");
                    }
                    else
                    {
                        await _userManager.AddToRoleAsync(user, "User");
                    }

                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);

                    _mailSender.SendMail(model.Email, "Confirm email", "Please confirm your email by clicking here: <a href=\"" + callbackUrl + "\">link</a>");

                    await _signInManager.SignInAsync(user, false);
                    return LocalRedirect(returnUrl);
                }

                AddError(result);
            }

            List<SelectListItem> listItems = new List<SelectListItem>();

            listItems.Add(new SelectListItem
            {
                Value = "Admin",
                Text = "Admin"
            });

            listItems.Add(new SelectListItem
            {
                Value = "User",
                Text = "User"
            });

            model.RoleList = listItems;

            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)//route values we are passing from our callbackUrl variable above
        {
            if (userId is null || code is null) return View("Error");

            var user = await _userManager.FindByIdAsync(userId);

            if (user is null) return View("Error");

            var result = await _userManager.ConfirmEmailAsync(user, code);

            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }


        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            LoginViewModel lvm = new LoginViewModel();

            return View(lvm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            returnUrl = returnUrl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
            
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, isPersistent:model.RememberMe,
                    lockoutOnFailure:true);

                if (result.Succeeded) return LocalRedirect(returnUrl);

                if (result.IsLockedOut) return View("Lockout");

                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt");
                    return View(model);
                }

                
            }
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            
            ForgotPasswordViewModel fpvm = new ForgotPasswordViewModel();

            return View(fpvm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user is null) return RedirectToAction("ForgotPasswordConfirmation");

                var code = await _userManager.GeneratePasswordResetTokenAsync(user);

                var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);

                _mailSender.SendMail(model.Email, "Reset Password", "Please reset your password by clicking here: <a href=\"" + callbackUrl + "\">link</a>");


                return RedirectToAction("ForgotPasswordConfirmation");
            }
            
            
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }


        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string? code = null)
        {
            return code == null ? View("Error") : View();
            
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user is null) return RedirectToAction("ResetPasswordConfirmation");

                var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);

                if (!result.Succeeded) AddError(result);

                return RedirectToAction("ResetPasswordConfirmation");

            }


            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public IActionResult ExternalLogin(string provider, string? returnUrl= null)//we are receiving the returnurl and the provider name which we set as the value in the login page
        {
            //if it is successful, this is the url we will be redirecting to
            var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl });

            //this will set the authentication properties based on the provider that is provided
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);

            return Challenge(properties, provider);
            //creates a challenge result
            //it is like instructing the provider that we dont know know who this user is, and the provider should validate him
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string? returnUrl= null, string? remoteError = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            //remoteError will be set by the provider in case there are any errors
            if (remoteError is not null)
            {
                ModelState.AddModelError(string.Empty, $"Error from external login provider: {remoteError}");
                return View(nameof(Login));
            }

            var info = await _signInManager.GetExternalLoginInfoAsync();

            if (info is null)
                return RedirectToAction(nameof(Login));

            //we signin the user with the external login provider, if the user already has a login
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false);

            if (result.Succeeded)
            {
                await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
                return LocalRedirect(returnUrl);
            }

            else
            {
                //if the user does not have an account, we will ask him to create one
                ViewData["ReturnUrl"] = returnUrl;
                ViewData["ProviderDisplayName"] = info.ProviderDisplayName;
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                var name = info.Principal.FindFirstValue(ClaimTypes.Name);
                return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = email, Name = name});
            }
  
        }

        [HttpPost]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string? returnUrl = null)
        {
            returnUrl = returnUrl ??= Url.Content("~/");

            if (ModelState.IsValid)
            {
                var info = await _signInManager.GetExternalLoginInfoAsync();

                if (info is null) return View("Error");

                var user = new AppUser { Email = model.Email, UserName = model.Email, Name = model.Name };

                var result = await _userManager.CreateAsync(user);

                if (result.Succeeded)
                {
                    await _userManager.AddToRoleAsync(user, "User");
                    result = await _userManager.AddLoginAsync(user, info);

                    if (result.Succeeded)
                    {
                        await _signInManager.SignInAsync(user, false);
                        await _signInManager.UpdateExternalAuthenticationTokensAsync(info);

                        return LocalRedirect(returnUrl);
                    }

                }

                AddError(result);


                
            }

            ViewData["ReturnUrl"] = returnUrl;

            return View(model);

            
        }

        [HttpGet]
        public async Task<IActionResult> EnableAuthenticator()
        {
            var user = await _userManager.GetUserAsync(User);

            //to reset any previous authentication key for the user
            await _userManager.ResetAuthenticatorKeyAsync(user);

            var token = await _userManager.GetAuthenticatorKeyAsync(user);
            var model = new TwoFactorAuthenticationViewModel { Token = token };

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> EnableAuthenticator(TwoFactorAuthenticationViewModel model)
        {
            var token = _userManager.Options.Tokens.AuthenticatorTokenProvider;

            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                var succeeded = await _userManager.VerifyTwoFactorTokenAsync(user, token, model.Code);

                if (succeeded)
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                }
                else
                {
                    ModelState.AddModelError(String.Empty, "An error occurred while processing two factor auth");
                    return View(model);
                }

            }

            return RedirectToAction("AuthenticatorConfirmation");
        }


        private void AddError(IdentityResult result)
        {
            foreach(var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
    }
}
