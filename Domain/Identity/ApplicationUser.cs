
using ChatApp.Domain.Entities;
using Domain.Entities;
using Domain.Enums;
using Microsoft.AspNetCore.Identity;

namespace ChatApp.Infrastructure.Identity;

public class ApplicationUser : IdentityUser<Guid>
{
    public string? DisplayName { get; set; }
    public string ?ProfileImageUrl { get; set; }
    public UserStatus Status { get; set; }
    public DateTimeOffset LastSeen { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    
    public IEnumerable<Message> Messages { get; set; } 
        = new List<Message>();
    public ICollection<Connection> Connections { get; set; } = new List<Connection>();
    public ICollection<MessageReaction> MessageReactions { get; set; } = new List<MessageReaction>();
    public ICollection<UserChat> UserChats { get; set; } = new List<UserChat>();
    public ICollection<MessageStatus>? MessageStatuses { get; set; } 
    public ICollection<RefreshToken>? RefreshTokens { get; set; }

}
