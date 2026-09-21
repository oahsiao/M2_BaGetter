using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using BaGetter.Authentication;
using BaGetter.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace BaGetter.Web.Pages.Admin;

[AllowAnonymous]
public sealed class LoginModel : PageModel
{
    private readonly IReadOnlyList<INugetCredentialValidator> _credentialValidators;

    public LoginModel(IEnumerable<INugetCredentialValidator> credentialValidators)
    {
        _credentialValidators = credentialValidators?.ToArray() ?? [];
    }

    [BindProperty]
    [Required]
    public string Username { get; set; }

    [BindProperty]
    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    [BindProperty(SupportsGet = true)]
    public string ReturnUrl { get; set; }

    public string ErrorMessage { get; private set; }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var validationResult = await ValidateCredentialsAsync(
            Username,
            Password,
            cancellationToken);

        if (validationResult == null ||
            !validationResult.Roles.Contains(
                AuthenticationConstants.AdminRole,
                StringComparer.OrdinalIgnoreCase))
        {
            ErrorMessage = "The username or password is invalid, or the account is not an administrator.";
            return Page();
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, validationResult.Username),
        };

        claims.AddRange(
            validationResult.Roles
                .Where(role => !string.IsNullOrWhiteSpace(role))
                .Select(role => new Claim(ClaimTypes.Role, role.Trim())));

        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(
                claims,
                AuthenticationConstants.AdminCookieAuthenticationScheme));

        await HttpContext.SignInAsync(
            AuthenticationConstants.AdminCookieAuthenticationScheme,
            principal);

        return !string.IsNullOrWhiteSpace(ReturnUrl) && Url.IsLocalUrl(ReturnUrl)
            ? LocalRedirect(ReturnUrl)
            : RedirectToPage("/Admin/Index");
    }

    public async Task<IActionResult> OnPostLogoutAsync()
    {
        await HttpContext.SignOutAsync(AuthenticationConstants.AdminCookieAuthenticationScheme);
        return RedirectToPage("/Admin/Login");
    }

    private async Task<NugetCredentialValidationResult> ValidateCredentialsAsync(
        string username,
        string password,
        CancellationToken cancellationToken)
    {
        foreach (var validator in _credentialValidators)
        {
            var result = await validator.ValidateAsync(username, password, cancellationToken);
            if (result != null)
            {
                return result;
            }
        }

        return null;
    }
}
