namespace JwtAuthentication
{
    public class ChangePasswordSchema
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string NewPassword { get; set; }
    }
}
