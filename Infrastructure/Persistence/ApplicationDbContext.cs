using ChatApp.Domain.Entities;
using ChatApp.Infrastructure.Identity;
using Domain.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace ChatApp.Infrastructure.Persistence
{
    
    public class ApplicationDbContext
        : IdentityDbContext<ApplicationUser, ApplicationRole, Guid>
    {
        public DbSet<Message> Messages { get; set; }
        public DbSet<UserChat> UserChats { get; set; }
        public DbSet<ApplicationUser> users { get; set; }
        public DbSet<ApplicationRole> roles { get; set; }
        public DbSet<MessageStatus> MessageStatuses { get; set; }
        public DbSet<RefreshToken>RefreshTokens { get; set; }

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

      

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            builder.ApplyConfigurationsFromAssembly(typeof(ApplicationDbContext).Assembly);
        }
    }
}
