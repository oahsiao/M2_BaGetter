using BaGetter.Authentication;
using BaGetter.Core;
using BaGetter.Web.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace BaGetter;

internal static class IServiceCollectionExtensions
{
    internal static BaGetterApplication AddNugetBasicHttpAuthentication(this BaGetterApplication app)
    {
        app.Services.AddAuthentication(options =>
        {
            // Breaks existing tests if the contains check is not here.
            if (!options.SchemeMap.ContainsKey(AuthenticationConstants.NugetBasicAuthenticationScheme))
            {
                options.AddScheme<NugetBasicAuthenticationHandler>(AuthenticationConstants.NugetBasicAuthenticationScheme, AuthenticationConstants.NugetBasicAuthenticationScheme);
                options.DefaultAuthenticateScheme = AuthenticationConstants.NugetBasicAuthenticationScheme;
                options.DefaultChallengeScheme = AuthenticationConstants.NugetBasicAuthenticationScheme;
            }
        })
        .AddCookie(AuthenticationConstants.AdminCookieAuthenticationScheme, options =>
        {
            options.LoginPath = "/admin/login";
            options.AccessDeniedPath = "/admin/login";
            options.Cookie.Name = "BaGetter.Admin";
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Strict;
            options.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.SameAsRequest;
            options.ExpireTimeSpan = TimeSpan.FromHours(8);
            options.SlidingExpiration = true;
        });

        return app;
    }

    internal static BaGetterApplication AddNugetBasicHttpAuthorization(this BaGetterApplication app, Action<AuthorizationPolicyBuilder>? configurePolicy = null)
    {
        app.Services.AddAuthorization(options =>
        {
            options.AddPolicy(AuthenticationConstants.NugetUserPolicy, policy =>
            {
                policy.RequireAuthenticatedUser();
                configurePolicy?.Invoke(policy);
            });
            options.AddPolicy(AuthenticationConstants.AdminPolicy, policy =>
            {
                policy
                    .AddAuthenticationSchemes(
                        AuthenticationConstants.NugetBasicAuthenticationScheme,
                        AuthenticationConstants.AdminCookieAuthenticationScheme)
                    .RequireAuthenticatedUser()
                    .RequireRole(AuthenticationConstants.AdminRole);
            });
        });

        return app;
    }
}
