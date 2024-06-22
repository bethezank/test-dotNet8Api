using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using DotnetStockAPI.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace DotnetStockAPI.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthenticateController : ControllerBase
{

    // สร้าง Object ของ ApplicationDbContext
    private readonly ApplicationDbContext _context;

    // ===

    // สร้าง Object จัดการ Users
    private readonly UserManager<IdentityUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IConfiguration _configuration;

    // ฟังก์ชันสร้าง Constructor สำหรับ initial ค่าของ ApplicationDbContext
    public AuthenticateController(
        ApplicationDbContext context,
        UserManager<IdentityUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IConfiguration configuration
    )
    {
        _context = context;
        _userManager = userManager;
        _roleManager = roleManager;
        _configuration = configuration;
    }

    // ===


    // ทดสอบเขียนฟังก์ชันการเชื่อมต่อ database
    [HttpGet("testconnectdb")]
    public void TestConnection()
    {
        if (_context.Database.CanConnect())
        {
            // ถ้าเชื่อมต่อได้จะแสดงข้อความ "Connected"
            Response.WriteAsync("Connected");
        }
        else
        {
            // ถ้าเชื่อมต่อไม่ได้จะแสดงข้อความ "Not Connected"
            Response.WriteAsync("Not Connected");
        }
    }

    // Register for User
    // Post api/authenticate/register-user
    [HttpPost]
    [Route("register-user")]
    public async Task<ActionResult> RegisterUser([FromBody] RegisterModel model)
    {
        // เช็คว่า username ซ้ำหรือไม่
        var userExists = await _userManager.FindByNameAsync(model.Username);
        if (userExists != null)
        {
            return StatusCode(
                StatusCodes.Status500InternalServerError,
                new ResponseModel
                {
                    Status = "Error",
                    Message = "User already exists!"
                }
            );
        }

        // เช็คว่า email ซ้ำหรือไม่
        userExists = await _userManager.FindByEmailAsync(model.Email);
        if (userExists != null)
        {
            return StatusCode(
                StatusCodes.Status500InternalServerError,
                new ResponseModel
                {
                    Status = "Error",
                    Message = "Email already exists!"
                }
            );
        }

        // สร้าง User
        IdentityUser user = new()
        {
            Email = model.Email,
            SecurityStamp = Guid.NewGuid().ToString(),
            UserName = model.Username
        };

        // สร้าง User ในระบบ
        var result = await _userManager.CreateAsync(user, model.Password);

        // ถ้าสร้างไม่สำเร็จ
        if (!result.Succeeded)
        {
            return StatusCode(
                StatusCodes.Status500InternalServerError,
                new ResponseModel
                {
                    Status = "Error",
                    Message = "User creation failed! Please check user details and try again."
                }
            );
        }

        // กำหนด Roles Admin, Manager, User
        // ถ้าไม่มี Role Admin ให้สร้าง Role Admin ใหม่
        if (!await _roleManager.RoleExistsAsync(UserRolesModel.Admin))
        {
            await _roleManager.CreateAsync(new IdentityRole(UserRolesModel.Admin));
        }

        // ถ้าไม่มี Role Manager ให้สร้าง Role Manager ใหม่
        if (!await _roleManager.RoleExistsAsync(UserRolesModel.Manager))
        {
            await _roleManager.CreateAsync(new IdentityRole(UserRolesModel.Manager));
        }

        // ถ้าไม่มี Role User ให้สร้าง Role User ใหม่ และเพิ่ม User ลงใน Role User
        if (!await _roleManager.RoleExistsAsync(UserRolesModel.User))
        {
            await _roleManager.CreateAsync(new IdentityRole(UserRolesModel.User));
            await _userManager.AddToRoleAsync(user, UserRolesModel.User);
        }
        else
        {
            await _userManager.AddToRoleAsync(user, UserRolesModel.User);
        }

        return Ok(new ResponseModel
        {
            Status = "Success",
            Message = "User registered successfully"
        });
    }


    // Login for User
    [HttpPost]
    [Route("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        var user = await _userManager.FindByNameAsync(model.Username!);

        // ถ้า login สำเร็จ
        if (user != null && await _userManager.CheckPasswordAsync(user, model.Password!))
        {
            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var token = GetToken(authClaims);

            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration = token.ValidTo,
                userData = new
                {
                    userName = user.UserName,
                    email = user.Email,
                    roles = userRoles
                }
            });
        }

        // ถ้า login ไม่สำเร็จ
        return Unauthorized();
    }

    // ฟังก์ชันสร้าง Token
    private JwtSecurityToken GetToken(List<Claim> authClaims)
    {
        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]!));

        var token = new JwtSecurityToken(
            issuer: _configuration["JWT:ValidIssuer"],
            audience: _configuration["JWT:ValidAudience"],
            expires: DateTime.Now.AddHours(24), // 24 hours
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
        );
        return token;

    }
}