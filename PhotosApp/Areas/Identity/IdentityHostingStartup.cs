using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using PhotosApp.Services.Authorization;
using PhotosApp.Services.TicketStores;

[assembly: HostingStartup(typeof(PhotosApp.Areas.Identity.IdentityHostingStartup))]
namespace PhotosApp.Areas.Identity
{
    public class IdentityHostingStartup : IHostingStartup
    {
        public void Configure(IWebHostBuilder builder)
        {
            builder.ConfigureServices((context, services) =>
            {
                services.AddDbContexts(context)
                    .AddManyAuthentications(context)
                    .AddScoped<IAuthorizationHandler, MustOwnPhotoHandler>()
                    .AddAuthorization()
                    .AddIdentity()
                    .AddIdentityOptions()
                    .AddTransient<EntityTicketStore>()
                    .ConfigureCookies()
                    .AddEmailSender(context);
            });
        }
    }
}