using AutoMapper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.MappBaseProfileing
{
   public class BaseMappingProfile<TSource, TDestination>:Profile where TSource : class where TDestination : class
    {
        protected BaseMappingProfile()
        {
            CreateMap<TSource, TDestination>().ReverseMap();
        }
    }
}
