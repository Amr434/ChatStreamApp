using ChatApp.Infrastructure.Identity;

namespace ChatApp.Domain.Entities
{
    public class Connection
    {
        public string ConnectionId { get; set; } = null!;
        public Guid UserId { get; set; }
        public ApplicationUser User { get; set; } = null!;
        public DateTime ConnectedAt { get; set; } = DateTime.UtcNow;
        public DateTime? DisconnectedAt { get; set; }
        public bool IsOnline => DisconnectedAt == null;
    }
}
