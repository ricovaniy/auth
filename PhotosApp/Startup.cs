using AutoMapper;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using PhotosApp.Areas;
using PhotosApp.Clients;
using PhotosApp.Clients.Models;
using PhotosApp.Data;
using PhotosApp.Models;
using PhotosApp.Services.Authorization;
using PhotosApp.Services.PasswordHasher;
using Serilog;

namespace PhotosApp
{
    public class Startup
    {
        private IWebHostEnvironment env { get; }
        private IConfiguration configuration { get; }

        public Startup(IWebHostEnvironment env, IConfiguration configuration)
        {
            this.env = env;
            this.configuration = configuration;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            const string oidcAuthority = "https://localhost:7001";
            var oidcConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                $"{oidcAuthority}/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever());
            services.AddSingleton<IConfigurationManager<OpenIdConnectConfiguration>>(oidcConfigurationManager);
            
            services.Configure<PhotosServiceOptions>(configuration.GetSection("PhotosService"));
            services.AddAuthentication(options =>
                {
                    options.DefaultSignInScheme = "Cookie";
                    options.DefaultChallengeScheme = "Passport";
                    options.DefaultScheme = "Cookie";
                })
                .AddCookie("Cookie", options =>
                {
                    options.Cookie.Name = "PhotosApp.Auth";
                    options.LogoutPath = "/Passport/Logout";
                })
                .AddPassport(oidcAuthority, oidcConfigurationManager);
            services.AddScoped<IAuthorizationHandler, MustOwnPhotoHandler>();

            services.AddAuthorization1();
            var mvc = services.AddControllersWithViews();
            services.AddRazorPages();
            if (env.IsDevelopment())
                mvc.AddRazorRuntimeCompilation();

            // NOTE: Подключение IHttpContextAccessor, чтобы можно было получать HttpContext там,
            // где это не получается сделать более явно.
            services.AddHttpContextAccessor();

            var connectionString = configuration.GetConnectionString("PhotosDbContextConnection")
                ?? "Data Source=PhotosApp.db";
            services.AddDbContext<PhotosDbContext>(o => o.UseSqlite(connectionString));
            // NOTE: Вместо Sqlite можно использовать LocalDB от Microsoft или другой SQL Server
            //services.AddDbContext<PhotosDbContext>(o =>
            //    o.UseSqlServer(@"Server=(localdb)\mssqllocaldb;Database=PhotosApp;Trusted_Connection=True;"));

            // services.AddScoped<IPhotosRepository, LocalPhotosRepository>();
            services.AddScoped<IPhotosRepository, RemotePhotosRepository>();
            services.AddPasswordHasher();
            services.AddAutoMapper(cfg =>
            {
                cfg.CreateMap<PhotoEntity, PhotoDto>().ReverseMap();
                cfg.CreateMap<PhotoEntity, Photo>().ReverseMap();

                cfg.CreateMap<EditPhotoModel, PhotoEntity>()
                    .ForMember(m => m.FileName, options => options.Ignore())
                    .ForMember(m => m.Id, options => options.Ignore())
                    .ForMember(m => m.OwnerId, options => options.Ignore());
            }, new System.Reflection.Assembly[0]);

            services.AddTransient<ICookieManager, ChunkingCookieManager>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app)
        {
            if (env.IsDevelopment())
                app.UseDeveloperExceptionPage();
            else
                app.UseExceptionHandler("/Exception");

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseStatusCodePagesWithReExecute("/StatusCode/{0}");

            app.UseSerilogRequestLogging();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute("default", "{controller=Photos}/{action=Index}/{id?}");
            });
        }
    }
}
