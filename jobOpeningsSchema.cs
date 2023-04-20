namespace JwtAuthentication
{
    public class jobOpeningsSchema
    {
        //Contains JobId,JobName,Salary,JobCompany,SubCategoryId
        public int JobId { get; set; }
        public string JobName { get; set; }
        public int Salary { get; set; }
        public string JobCompany { get; set; }
        public int SubCategoryId { get; set; }
    }
}
