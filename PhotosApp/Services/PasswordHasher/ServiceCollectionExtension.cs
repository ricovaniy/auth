using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PhotosApp.Areas.Identity.Data;

namespace PhotosApp.Services.PasswordHasher
{
    public static class ServiceCollectionExtension
    {
        public static IServiceCollection AddPasswordHasher(this IServiceCollection services)
        {
            return services
                .Configure<PasswordHasherOptions>(o =>
                {
                    o.CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV3;
                    o.IterationCount = 12000;
                })
                .AddScoped<IPasswordHasher<PhotosAppUser>, SimplePasswordHasher<PhotosAppUser>>();
        }
    }
}