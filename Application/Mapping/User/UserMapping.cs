using Application.DTOs.User;
using AutoMapper;
using ChatApp.Infrastructure.Identity;
namespace Application.UserMapping
{

    public class UserMapping : Profile
    {
        public UserMapping()
        {
            CreateMap<UserDto, ApplicationUser>()
                .ForMember(x => x.UserName, y => y.MapFrom(t => t.UserName))
                .ForMember(x => x.NormalizedEmail, y => y.MapFrom(t => t.Email))
                .ForMember(x => x.ProfileImageUrl, y => y.MapFrom(t => t.ProfileImageUrl))
                .ForMember(x => x.LastSeen, y => y.MapFrom(t => t.LastSeen))
                .ForMember(x => x.CreatedAt, y => y.MapFrom(t => t.CreatedAt))
                .ForMember(x => x.Status, y => y.MapFrom(t => t.Status))
                .ForMember(x => x.DisplayName, y => y.MapFrom(t => t.DisplayName))
                .ReverseMap();

            CreateMap<RegisterDto, ApplicationUser>()
               .ForMember(x => x.UserName, y => y.MapFrom(t => t.UserName))
               .ForMember(x => x.Email, y => y.MapFrom(t => t.Email))
               .ReverseMap();

            CreateMap<AdminUpdateUserDto, ApplicationUser>()
                .ForMember(x => x.Id, y => y.MapFrom(t => t.Id))
                .ForMember(x => x.UserName, y => y.MapFrom(t => t.UserName))
                .ForMember(x => x.Email, y => y.MapFrom(t => t.Email))
                .ForMember(x => x.DisplayName, y => y.MapFrom(t => t.DisplayName))
                .ForMember(x => x.PhoneNumber, y => y.MapFrom(t => t.PhoneNumber))
                .ForMember(x => x.ProfileImageUrl, y => y.MapFrom(t => t.ProfileImageUrl))
                .ForMember(x => x.LockoutEnabled, y => y.MapFrom(t => t.IsLocked))
                .ForMember(x => x.Status, y => y.MapFrom(t => t.Status))                
                .ReverseMap(); 
            
            CreateMap<CreateUserByAdminDto, ApplicationUser>()
                .ForMember(x => x.Email, y => y.MapFrom(t => t.Email))
                .ForMember(x => x.DisplayName, y => y.MapFrom(t => t.DisplayName))
                .ReverseMap();
        }
    }
}