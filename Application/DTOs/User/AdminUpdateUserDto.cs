using Domain.Enums;

namespace Application.DTOs.User
{
    public class AdminUpdateUserDto
    {
        public string Id { get; set; } = default!;

        public string? DisplayName { get; set; }
        public string? UserName { get; set; }
        public string? Email { get; set; }
        public string? PhoneNumber { get; set; }
        public string? ProfileImageUrl { get; set; }

        public UserStatus? Status { get; set; }  
        public bool? IsLocked { get; set; }      

        public List<string>? Roles { get; set; }

        public string? UpdatedBy { get; set; }
    }
}
