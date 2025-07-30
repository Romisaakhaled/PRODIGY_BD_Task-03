using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthenticationAndAuthorization.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        // 🔐 ده Endpoint محمي بالتوكن
        [Authorize]
        [HttpGet("me")]
        public IActionResult GetMe()
        {
            var username = User.Identity?.Name;
            return Ok(new
            {
                Message = $"Hi {username}, you are authorized!"
            });
        }

        // ✅ وده مش محمي
        [AllowAnonymous]
        [HttpGet("public")]
        public IActionResult GetPublic()
        {
            return Ok("This is a public endpoint.");
        }
    }
}

