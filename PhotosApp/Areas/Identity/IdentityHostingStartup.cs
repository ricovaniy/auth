using System;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PhotosApp.Areas.Identity.Data;
using PhotosApp.Services;
using PhotosApp.Services.Authorization;
using PhotosApp.Services.TicketStores;

[assembly: HostingStartup(typeof(PhotosApp.Areas.Identity.IdentityHostingStartup))]
namespace PhotosApp.Areas.Identity
{
    public class IdentityHostingStartup : IHostingStartup
    {
        public void Configure(IWebHostBuilder builder)
        {
            builder.ConfigureServices((context, services) => {
                services.AddDbContext<UsersDbContext>(options =>
                    options.UseSqlite(
                        context.Configuration.GetConnectionString("UsersDbContextConnection")));
                services.AddDbContext<TicketsDbContext>(options =>
                    options.UseSqlite(
                        context.Configuration.GetConnectionString("TicketDbContextConnection")));
                
                services.AddAuthentication()
                    .AddGoogle("Google", options =>
                    {
                        options.ClientId = context.Configuration["Authentication:Google:ClientId"];
                        options.ClientSecret = context.Configuration["Authentication:Google:ClientSecret"];
                    });
                
                services.AddScoped<IAuthorizationHandler, MustOwnPhotoHandler>();
                services.AddAuthorization(o =>
                {
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
                });
                services.AddDefaultIdentity<PhotosAppUser>()
                    .AddRoles<IdentityRole>()
                    .AddClaimsPrincipalFactory<CustomClaimsPrincipalFactory>()
                    .AddEntityFrameworkStores<UsersDbContext>()
                    .AddPasswordValidator<UsernameAsPasswordValidator<PhotosAppUser>>()
                    .AddErrorDescriber<RussianIdentityErrorDescriber>();
            });

            builder.ConfigureServices((context, services) =>
            {
                services.Configure<IdentityOptions>(options =>
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
                services.AddTransient<EntityTicketStore>();
                services.ConfigureApplicationCookie(options =>
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
            });
        }
    }
}