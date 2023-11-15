using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using SimpleJWT.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace YourNamespace
{
    [ApiController]
    [Route("[controller]")]
    public class AuthenticationController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public AuthenticationController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginModel request)
        {
            // Implement your actual login logic here, e.g., validate username and password
            // For this example, we'll assume successful login
            if (IsValidUser(request.UserName, request.Password))
            {
                var token = GenerateJwtToken(request.UserName);
                return Ok(new { Token = token });
            }

            return Unauthorized("Invalid username or password");
        }

        
        private bool IsValidUser(string username, string password)
        {
            // In a real application, you would typically query your database
            // or an external identity provider to validate user credentials.
            // For this example, we'll use a hardcoded list of users.

            var users = new List<LoginModel>
            {
                new LoginModel { UserName = "Alisha1", Password = "Alisha1" },
                // Add more users as needed
            };

            // Check if the provided username and password match any user in the list.
            return users.Any(user => user.UserName == username && user.Password == password);
        }

        // Generate a JWT token in this method 
        

        private string GenerateJwtToken(string username)
        {
            var jwtKey = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]);
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, username)
                }),
                Expires = DateTime.UtcNow.AddHours(1), // Token expiration time
                Audience = _configuration["Jwt:Audience"], // Set the audience claim
                Issuer = _configuration["Jwt:Issuer"], // Set the issuer claim
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(jwtKey), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }

   
}
