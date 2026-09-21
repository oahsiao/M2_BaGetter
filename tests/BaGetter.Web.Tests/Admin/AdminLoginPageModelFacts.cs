using System.IO;
using System.Threading;
using System.Threading.Tasks;
using BaGetter.Authentication;
using BaGetter.Core;
using BaGetter.Web.Pages.Admin;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace BaGetter.Web.Tests.Admin;

public sealed class AdminLoginPageModelFacts
{
    [Fact]
    public async Task Login_WithAdminCredentials_CreatesCookieAndRedirects()
    {
        var validator = new Mock<INugetCredentialValidator>();
        validator
            .Setup(service => service.ValidateAsync(
                "admin",
                "password",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new NugetCredentialValidationResult("admin", ["Admin"]));

        await using var services = CreateServices();
        var context = CreateHttpContext(services);
        var model = new LoginModel([validator.Object])
        {
            PageContext = new PageContext { HttpContext = context },
            Username = "admin",
            Password = "password",
        };

        var result = await model.OnPostAsync(CancellationToken.None);

        var redirect = Assert.IsType<RedirectToPageResult>(result);
        Assert.Equal("/Admin/Index", redirect.PageName);
        Assert.Contains(
            "BaGetter.Admin=",
            context.Response.Headers.SetCookie.ToString());
    }

    [Fact]
    public async Task Login_WithoutAdminRole_IsRejected()
    {
        var validator = new Mock<INugetCredentialValidator>();
        validator
            .Setup(service => service.ValidateAsync(
                "reader",
                "password",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new NugetCredentialValidationResult("reader", ["Reader"]));

        await using var services = CreateServices();
        var context = CreateHttpContext(services);
        var model = new LoginModel([validator.Object])
        {
            PageContext = new PageContext { HttpContext = context },
            Username = "reader",
            Password = "password",
        };

        var result = await model.OnPostAsync(CancellationToken.None);

        Assert.IsType<PageResult>(result);
        Assert.NotEmpty(model.ErrorMessage);
        Assert.False(context.Response.Headers.ContainsKey("Set-Cookie"));
    }

    private static ServiceProvider CreateServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services
            .AddAuthentication()
            .AddCookie(
                AuthenticationConstants.AdminCookieAuthenticationScheme,
                options => options.Cookie.Name = "BaGetter.Admin");
        return services.BuildServiceProvider();
    }

    private static DefaultHttpContext CreateHttpContext(ServiceProvider services)
    {
        return new DefaultHttpContext
        {
            RequestServices = services,
            Response =
            {
                Body = new MemoryStream(),
            },
        };
    }
}
