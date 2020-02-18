using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Application.Areas.Identity.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Localization;
using System.Collections.Specialized;

namespace Application.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class RegisterModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<RegisterModel> _logger;
        private readonly IEmailSender _emailSender;

        public RegisterModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ILogger<RegisterModel> logger,
            IEmailSender emailSender
            )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _emailSender = emailSender;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public string ReturnUrl { get; set; }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Pole '{0}' jest wymagane")]
            [EmailAddress(ErrorMessage = "Pole '{0}' zawiera nie prawidłowe dane")]
            [Display(Name = "Email")]
            public string Email { get; set; }

            [Required(ErrorMessage = "Pole '{0}' jest wymagane")]
            [StringLength(100, ErrorMessage = "{0} musi mieć przynajmniej {2} znaków, oraz {1} znaków.", MinimumLength = 6)]
            [DataType(DataType.Password)]
            [Display(Name = "Hasło")]
            public string Password { get; set; }

            [DataType(DataType.Password)]
            [Display(Name = "Powtórz Hasło")]
            [Compare("Password", ErrorMessage = "Hasła do siebie nie pasują.")]
            public string ConfirmPassword { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            ReturnUrl = returnUrl;
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = Input.Email, Email = Input.Email };
                var result = await _userManager.CreateAsync(user, Input.Password);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User created a new account with password.");

                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                    var callbackUrl = Url.Page(
                        "/Account/ConfirmEmail",
                        pageHandler: null,
                        values: new { area = "Identity", userId = user.Id, code = code },
                        protocol: Request.Scheme);

                    await _emailSender.SendEmailAsync(Input.Email, "Potwierdź swój email",
                        $"Aby potwierdzić swój email <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>kliknij tutaj</a>.");

                    if (_userManager.Options.SignIn.RequireConfirmedAccount)
                    {
                        return RedirectToPage("RegisterConfirmation", new { email = Input.Email });
                    }
                    else
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        return LocalRedirect(returnUrl);
                    }
                }

                NameValueCollection PolishErrors = new NameValueCollection()
                {
                    { "DefaultError", "Nieznany błąd" },
                    { "DuplicateEmail", $"Email '{Input.Email}' jest zajęty." },
                    { "DuplicateUserName", $"Email '{Input.Email}' jest zajęty." },
                    { "PasswordRequireDigit", "Hasło musi zawierać przynajmniej jedną cyfrę ('0'-'9')." },
                    { "PasswordRequiresLower", "Hasło musi zawierać przynajmniej jeden mały znak ('a' - 'z')." },
                    { "PasswordRequiresNonAlphanumeric", "Hasło musi zawierać przynajmniej jeden niealfanumeryczny znak" },
                    { "PasswordRequiresUpper", "Hasło musi zawierać przynajmniej jeden duży znak ('A' - 'Z')." }
                };

                foreach (var error in result.Errors)
                {
                    if (PolishErrors[error.Code] != null)
                    {
                        ModelState.AddModelError(string.Empty, PolishErrors[error.Code]);
                    }
                    else
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
            }

            // If we got this far, something failed, redisplay form
            return Page();
        }
    }
}
