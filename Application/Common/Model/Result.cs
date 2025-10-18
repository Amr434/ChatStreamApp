using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Common.Model
{
   public class Result<T>
    {
        public bool Success { get; init; }
        public string ? Error{  get; init; }
        public  T?Value { get; init; }
        private Result(bool success,T ? value=default, string? error=null) 
        {
           Success = success;
            Error = error;
            Value = value;
        }
        public static Result<T> SuccessResult(T value) => new(true, value);
        public static Result<T> Failure(string? error) => new(false, default, error);

    }
    public class Result
    {
        public bool Success { get; init; }
        public string? Error { get; init; }

        private Result(bool success,string ?error=null) 
        { 
            Success = success;
            Error=error;
        }
        public static Result SuccessResult()=>new(true);
        public static Result Failure(string error)=>new(false,error);
    }
}
