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

        }
    }
}