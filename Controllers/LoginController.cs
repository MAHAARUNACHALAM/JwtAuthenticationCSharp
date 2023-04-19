using Microsoft.AspNet.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using JwtAuthentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;


// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JwtAuthentication.Controllers
{


    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        IConfiguration configuration;
        SqlConnection con;
        public LoginController(IConfiguration config)
        {
            configuration = config;
            con = new SqlConnection(configuration.GetConnectionString("DB"));
        }

        // GET: api/<LoginController>
        [HttpGet]
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }
        //POST: api/<LoginController>
        [HttpPost]
        //signup method for employee registration and password hashing and save to database
        public IActionResult Signup([FromBody] EmployeeLogin employee)
        {
            //check if the employee already exists
            if (employee == null)
            {
                return BadRequest("Invalid client request");
            }
            //hash the password with salt value
            var passwordHash = new PasswordHasher<EmployeeLogin>();
            employee.Password = passwordHash.HashPassword(employee, employee.Password);
            //log the employee details
            Console.WriteLine("Employee Id: " + employee.Id);
            Console.WriteLine("Employee Username: " + employee.Username);
            Console.WriteLine("Employee Email: " + employee.Email);
            Console.WriteLine("Employee Password: " + employee.Password);
            //save the employee to the database
            con.Open();

            SqlCommand cmd = new SqlCommand("insert into EmployeeLogin values(@id,@username,@email,@password)", con);
            cmd.Parameters.AddWithValue("@id", employee.Id);
            cmd.Parameters.AddWithValue("@username", employee.Username);
            cmd.Parameters.AddWithValue("@email", employee.Email);
            cmd.Parameters.AddWithValue("@password", employee.Password);
            cmd.ExecuteNonQuery();
            
            con.Close();
                                                                            
            return Ok(employee);
        }

        //POST: api/<LoginController>/login
        [HttpPost]
        [Route("login")]
        //login method for employee login and generate jwt token for authentication
        public IActionResult Login([FromBody] EmployeeLogin employee)
        {
            //check if the employee already exists
            if (employee == null)
            {
                return BadRequest("Invalid client request");
            }
            //check if the employee exists in the database
            con.Open();
            SqlCommand cmd = new SqlCommand("select * from EmployeeLogin where username=@Username", con);
            cmd.Parameters.AddWithValue("@Username", employee.Username);
            SqlDataReader reader = cmd.ExecuteReader();
            //Generate jwt token for authentication if passwod matches and also import the necessary package
            if (reader.Read())
            {
                var passwordHash = new PasswordHasher<EmployeeLogin>();
                var result = passwordHash.VerifyHashedPassword(employee, reader["password"].ToString(), employee.Password);
                if (result == Microsoft.AspNetCore.Identity.PasswordVerificationResult.Success)
                {
                    var claims = new[]
                    {
                        new Claim(JwtRegisteredClaimNames.Sub, employee.Username),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                    };
                    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]));
                    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                    var token = new JwtSecurityToken(
                                               configuration["Jwt:Issuer"],
                                               configuration["Jwt:Issuer"],
                                               claims,
                                               expires: DateTime.Now.AddMinutes(30),
                                               signingCredentials: creds);
                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(token)
                    });
                }
            }
            con.Close();
            return Unauthorized();

        }

    }
}
