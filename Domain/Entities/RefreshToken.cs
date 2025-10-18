using ChatApp.Infrastructure.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Entities
{
    public class RefreshToken
    {
        public Guid Id { get; set; }
        public Guid UserId { get; set; } 
        public string Token {  get; set; }=null!;
        public DateTime ExpiresAt { get; set; }
        public DateTime CreatedAt { get; set; }
        public bool isRevoked {  get; set; }=false;
        public bool isExpired => DateTime.UtcNow >= ExpiresAt;
        public bool IsActive => !isExpired && !isRevoked;
        public ApplicationUser ?User { get; set; }
    }
}
