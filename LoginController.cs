using jwtWebApi.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.Intrinsics.Arm;
using System.Security.Claims;
using System.Text;

namespace jwtWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private IConfiguration _configuration;

        public LoginController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        private Users Authenticate(Users users)
        {
            Users _user = null;
            if(users.UserName== "apitest" && users.Password== "test123")
            {
                _user=new Users
                {
                    UserName= users.UserName,
                    Password=users.Password,
                };
            }
            return _user;


        }
        private string GenerateToken(Users users)
        {
           var header = new JwtHeader(new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["jwt:key"])),
            SecurityAlgorithms.HmacSha256
        ));

        // Payload oluştur
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, "subject"),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            // Diğer istediğiniz bilgileri ekleyebilirsiniz
        };

        var payload = new JwtPayload(claims);

        // JWT oluştur
        var jwt = new JwtSecurityToken(header, payload);
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.WriteToken(jwt);

        return token;
        }
        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login(Users users)
        {
            IActionResult action = Unauthorized();
            var user = Authenticate(users);
            if(user != null) {
                var token = GenerateToken(user);
                action=  Ok(new { token = token });

            }
            return action;
        }
    }
}
