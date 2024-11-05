using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using PhotosApp.Areas.Identity.Data;
using PhotosApp.Services;
using PhotosApp.Services.Authorization;
using PhotosApp.Services.TicketStores;

namespace PhotosApp.Areas
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddAuthorization(this IServiceCollection services)
        {
            return services.AddAuthorization(o =>
            {
                o.DefaultPolicy = new AuthorizationPolicyBuilder(
                        JwtBearerDefaults.AuthenticationScheme,
                        IdentityConstants.ApplicationScheme)
                    .RequireAuthenticatedUser()
                    .Build();
                o.AddPolicy(
                    "Beta",
                    policyBuilder =>
                    {
                        policyBuilder.RequireAuthenticatedUser();
                        policyBuilder.RequireClaim("testing", "beta");
                    });
                o.AddPolicy(
                    "CanAddPhoto",
                    policyBuilder =>
                    {
                        policyBuilder.RequireAuthenticatedUser();
                        policyBuilder.RequireClaim("subscription", "paid");
                    });
                o.AddPolicy(
                    "MustOwnPhoto",
                    policyBuilder =>
                    {
                        policyBuilder.RequireAuthenticatedUser();
                        policyBuilder.AddRequirements(new MustOwnPhotoRequirement());
                    });
                o.AddPolicy("Dev",
                    policyBuilder =>
                    {
                        policyBuilder.RequireRole(Roles.Dev)
                            .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme,
                                IdentityConstants.ApplicationScheme);
                    });
            });
        }

        public static IServiceCollection AddDbContexts(this IServiceCollection services, WebHostBuilderContext context)
        {
            return services.AddDbContext<UsersDbContext>(options =>
                    options.UseSqlite(
                        context.Configuration.GetConnectionString("UsersDbContextConnection")))
                .AddDbContext<TicketsDbContext>(options =>
                    options.UseSqlite(
                        context.Configuration.GetConnectionString("TicketDbContextConnection")));
        }

        public static IServiceCollection AddManyAuthentications(this IServiceCollection services,
            WebHostBuilderContext context)
        {
            services.AddAuthentication()
                .AddBearer()
                .AddGoogle(context)
                .AddPassport();
            return services;
        }

        public static IServiceCollection AddIdentity(this IServiceCollection services)
        {
            services.AddDefaultIdentity<PhotosAppUser>()
                .AddRoles<IdentityRole>()
                .AddClaimsPrincipalFactory<CustomClaimsPrincipalFactory>()
                .AddEntityFrameworkStores<UsersDbContext>()
                .AddPasswordValidator<UsernameAsPasswordValidator<PhotosAppUser>>()
                .AddErrorDescriber<RussianIdentityErrorDescriber>();

            services.ConfigureExternalCookie(options =>
            {
                options.Cookie.Name = "PhotosApp.Auth.External";
                options.Cookie.HttpOnly = true;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                options.SlidingExpiration = true;
            });
            return services;
        }

        public static IServiceCollection AddIdentityOptions(this IServiceCollection services)
        {
            return services.Configure<IdentityOptions>(options =>
            {
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = true;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = false;
                options.Password.RequiredLength = 6;
                options.Password.RequiredUniqueChars = 1;

                options.SignIn.RequireConfirmedEmail = false;
                options.SignIn.RequireConfirmedPhoneNumber = false;
                options.SignIn.RequireConfirmedAccount = false;
            });
        }

        public static IServiceCollection ConfigureCookies(this IServiceCollection services)
        {
            return services.ConfigureApplicationCookie(options =>
            {
                var serviceProvider = services.BuildServiceProvider();
                options.SessionStore = serviceProvider.GetRequiredService<EntityTicketStore>();
                options.AccessDeniedPath = "/Identity/Account/AccessDenied";
                options.Cookie.Name = "PhotosApp.Auth";
                options.Cookie.HttpOnly = true;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
                options.LoginPath = "/Identity/Account/Login";
                options.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;
                options.SlidingExpiration = true;
            });
        }

        public static IServiceCollection AddEmailSender(this IServiceCollection services, WebHostBuilderContext context)
        {
            return services.AddTransient<IEmailSender, SimpleEmailSender>(serviceProvider =>
                new SimpleEmailSender(
                    serviceProvider.GetRequiredService<ILogger<SimpleEmailSender>>(),
                    serviceProvider.GetRequiredService<IWebHostEnvironment>(),
                    context.Configuration["SimpleEmailSender:Host"],
                    context.Configuration.GetValue<int>("SimpleEmailSender:Port"),
                    context.Configuration.GetValue<bool>("SimpleEmailSender:EnableSSL"),
                    context.Configuration["SimpleEmailSender:UserName"],
                    context.Configuration["SimpleEmailSender:Password"]
                ));
        }

        private static AuthenticationBuilder AddBearer(this AuthenticationBuilder builder)
        {
            return builder.AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = false;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = TemporaryTokens.SigningKey
                };
                options.Events = new JwtBearerEvents
                {
                    OnMessageReceived = c =>
                    {
                        c.Token = c.Request.Cookies[TemporaryTokens.CookieName];
                        return Task.CompletedTask;
                    }
                };
            });
        }

        private static AuthenticationBuilder AddGoogle(this AuthenticationBuilder builder,
            WebHostBuilderContext context)
        {
            return builder.AddOpenIdConnect(
                authenticationScheme: "Google",
                displayName: "Google",
                options =>
                {
                    options.Authority = "https://accounts.google.com/";
                    options.ClientId = context.Configuration["Authentication:Google:ClientId"];
                    options.ClientSecret = context.Configuration["Authentication:Google:ClientSecret"];

                    options.CallbackPath = "/signin-google";
                    options.SignedOutCallbackPath = "/signout-callback-google";
                    options.RemoteSignOutPath = "/signout-google";
                    options.Scope.Add("email");
                });
        }

        private static AuthenticationBuilder AddPassport(this AuthenticationBuilder builder)
        {
            return builder.AddOpenIdConnect("Passport", "Паспорт", options =>
            {
                options.Authority = "https://localhost:7001/";

                options.ClientId = "Photos App by OIDC";
                options.ClientSecret = "secret";
                options.ResponseType = "code";
                
                options.Scope.Add("email");

                options.CallbackPath = "/signin-passport";

                // NOTE: все эти проверки токена выполняются по умолчанию, указаны для ознакомления
                options.TokenValidationParameters.ValidateIssuer = true; // проверка издателя
                options.TokenValidationParameters.ValidateAudience = true; // проверка получателя
                options.TokenValidationParameters.ValidateLifetime = true; // проверка не протух ли
                options.TokenValidationParameters.RequireSignedTokens = true; // есть ли валидная подпись издателя
            });
        }
    }
}