using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext Context;

        public AccountController(DataContext context)
        {
            this.Context = context;
        }

        // api/users/
        [HttpPost("register")]
        public async Task<ActionResult<AppUser>> Register(RegisterDto registerDto) 
        {
            if(await UserExists(registerDto.Username)) return BadRequest("Username already exists");

            using var hmax = new HMACSHA512();

            var user = new AppUser 
            {
                UserName = registerDto.Username.ToLower(),
                PasswordHash = hmax.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmax.Key
            };

            this.Context.Users.Add(user);
            await this.Context.SaveChangesAsync();

            return user;
        }

        private async Task<bool> UserExists(string username) {
            return await Context.Users.AnyAsync(user => user.UserName == username.ToLower());
        }

        [HttpPost("login")]
        public async Task<ActionResult<AppUser>> Loging(LoginDto loginDto)
        {
            var user = await Context.Users.SingleOrDefaultAsync(user => user.UserName == loginDto.Username);

            if(user == null) return Unauthorized("invalid Username");

            using var hmax = new HMACSHA512(user.PasswordSalt);

            var computedHash = hmax.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

            for (int i = 0; i < computedHash.Length; i++)
            {
                if(computedHash[i] != user.PasswordHash[i])
                    return Unauthorized("Wrong password");
                    
            }

            return user;

        }
    }
}