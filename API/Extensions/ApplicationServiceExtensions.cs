using Microsoft.Extensions.DependencyInjection;

namespace ChatApp.API.Extensions
{
    public static class ApplicationServiceExtensions
    {
        public static IServiceCollection AddApplication(this IServiceCollection services)
        {
            services.AddAutoMapper(typeof(Application.UserMapping.UserMapping).Assembly);
            return services;
        }
    }
}
