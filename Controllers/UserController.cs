using Microsoft.AspNet.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;



// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JwtAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        IConfiguration configuration;
        SqlConnection con;
        public UserController(IConfiguration config)
        {
            configuration = config;
            con = new SqlConnection(configuration.GetConnectionString("DB"));
        }

        //POST: api/signup
        [HttpPost]
        [Route("signup")]
        //signup method for employee registration and password hashing and save to database
        public IActionResult Signup([FromBody] userSchema employee)
        {
            //check if the employee already exists
            if (employee == null)
            {
                return BadRequest("Invalid client request");
            }
            //hash the password with salt value
            var passwordHash = new PasswordHasher<userSchema>();
            employee.Password = passwordHash.HashPassword(employee, employee.Password);
            //log the employee details
            Console.WriteLine("Employee Id: " + employee.Id);
            Console.WriteLine("Employee Username: " + employee.Username);
            Console.WriteLine("Employee Email: " + employee.Email);
            Console.WriteLine("Employee Password: " + employee.Password);
            
            //save the employee to the database
            con.Open();

            SqlCommand cmd = new SqlCommand("insert into UserId values(@Id,@Username,@Email,@Password,@RoleId)", con);
            cmd.Parameters.AddWithValue("@Id", employee.Id);
            cmd.Parameters.AddWithValue("@Username", employee.Username);
            cmd.Parameters.AddWithValue("@Email", employee.Email);
            cmd.Parameters.AddWithValue("@Password", employee.Password);
            cmd.Parameters.AddWithValue("@RoleId", employee.RoleId);
            cmd.ExecuteNonQuery();

            con.Close();

            return Ok(employee);
        }

        //POST: api/login
        [HttpPost]
        [Route("login")]
        //login method for employee login and password verification take email and password as input
        //Take only email and password as input from the userschema
        public IActionResult Login([FromBody] LoginSchema employee)
        {
            //check if the employee already exists
            //if username or password is null return bad request
            if (employee.Email == null || employee.Password == null)
            {
                return BadRequest("Invalid client request");
            }
            //check if the employee exists in the database
            con.Open();
            SqlCommand cmd = new SqlCommand("select * from UserId where Email=@Email", con);
            cmd.Parameters.AddWithValue("@Email",employee.Email);
            SqlDataReader reader = cmd.ExecuteReader();
            //Generate jwt token for authentication if passwod matches and also import the necessary package
            if (reader.Read())
            {
                var passwordHash = new PasswordHasher<LoginSchema>();
                var result = passwordHash.VerifyHashedPassword(employee,reader["Password"].ToString(), employee.Password);

                if (result == Microsoft.AspNetCore.Identity.PasswordVerificationResult.Success)
                {
                    var claims = new[]
                    {
                        new Claim(JwtRegisteredClaimNames.Sub, reader["RoleId"].ToString()),
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
        [HttpPost]
        [Route("logout")]
        public IActionResult Logout()
        {
            return Ok();
        }
        [HttpPost]
        [Route("changepassword")]
        public IActionResult changePassword([FromBody] ChangePasswordSchema employee)
        {
            //Check the current password and update it
            if (employee.Email == null || employee.Password == null)
            {
                return BadRequest("Invalid client request");
            }
            //check if current password is correct
            con.Open();
            SqlCommand cmd = new SqlCommand("select * from UserId where Email=@Email", con);
            cmd.Parameters.AddWithValue("@Email", employee.Email);
            SqlDataReader reader = cmd.ExecuteReader();
            //update the password if current password is correct
            if (reader.Read())
            {
                var passwordHash = new PasswordHasher<ChangePasswordSchema>();
                var result = passwordHash.VerifyHashedPassword(employee, reader["Password"].ToString(), employee.Password);
                if (result == Microsoft.AspNetCore.Identity.PasswordVerificationResult.Success)
                {
                    //hash the password with salt value
                    var passwordHash1 = new PasswordHasher<ChangePasswordSchema>();
                    employee.Password = passwordHash1.HashPassword(employee, employee.Password);
                    //update the password
                    SqlCommand cmd1 = new SqlCommand("update UserId set Password=@Password where Email=@Email", con);
                    cmd1.Parameters.AddWithValue("@Email", employee.Email);
                    cmd1.Parameters.AddWithValue("@Password", employee.NewPassword);
                    cmd1.ExecuteNonQuery();
                    con.Close();
                    return Ok(employee);
                }
            }
            con.Close();
            return Unauthorized();
        }

        //Validate token
        [HttpGet]
        [Route("validate")]
        public IActionResult Validate(String token)
        {
            //Check whether token is valid or not
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(configuration["Jwt:Key"]);
            //include try catch block to handle exceptions
            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);
                //if token is valid return ok
                if (validatedToken != null)
                {
                    var jwtToken = (JwtSecurityToken)validatedToken;
                    var RoleId = jwtToken.Claims.First(x => x.Type == "sub").Value;
                    return Ok(RoleId);
                }
                return Unauthorized();
            }
            catch (Exception e)
            {
                return Unauthorized();
            }
           
        }

        
    }
}
