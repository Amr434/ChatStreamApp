using Domain.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs.User
{
    public class UserDto
    {
        public string UserName { get; set; }
        public string? DisplayName { get; set; }
        public string? Email { get; set; }
        public string? ProfileImageUrl { get; set; }
        public UserStatus Status { get; set; }
        public DateTimeOffset? LastSeen { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
    }

}
