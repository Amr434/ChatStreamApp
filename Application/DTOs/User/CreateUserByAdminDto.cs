using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs.User
{
    public class CreateUserByAdminDto
    {
        public string Email { get; set; }
        public string? DisplayName { get; set; }
        public string Password { get; set; }
        public IFormFile? ProfileImage { get; set; }
        public List<string>? Roles { get; set; }
    }
}
