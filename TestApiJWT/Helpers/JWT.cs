namespace TestApiJWT.Helpers
{
    public class JWT
    {
        // To map this properites in appsittings to can use it in Services
        public string Key { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public double DurationInMinutes { get; set; }
    }
}
