using System;
using System.IO;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Ocelot.Middleware;
using Ocelot.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using WebApi.Helpers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace MyWeb {
    public class Program {
        public static void Main(string[] args) {
            new WebHostBuilder()
               .UseKestrel()
               .UseContentRoot(Directory.GetCurrentDirectory())
               .ConfigureAppConfiguration((hostingContext, config) => {
                   config
                       .SetBasePath(hostingContext.HostingEnvironment.ContentRootPath)
                       .AddJsonFile("appsettings.json", true, true)
                       .AddJsonFile("ocelot.json", true, true)
                       .AddEnvironmentVariables();
               })
               .ConfigureServices(s => {
                   s.AddAuthentication()
                       .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>("BasicAuthentication", null);
                   s.AddScoped<IUserService, UserService>();
                   s.AddOcelot();
               })
               .ConfigureLogging((hostingContext, logging) => {

               })
               .Configure(app => {
                   app.UseAuthentication();
                   app.UseOcelot().Wait();

               })
               .Build()
               .Run();
        }
    }
}
