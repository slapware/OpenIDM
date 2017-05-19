using System; // added for String
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using StackExchange.Redis; // Addition for Redis
using System.Configuration; // for connection string

namespace ResiIdentity.Models
{
    // You can add profile data for the user by adding more properties to your ApplicationUser class, please visit http://go.microsoft.com/fwlink/?LinkID=317594 to learn more.
    public class ApplicationUser : IdentityUser, StackRedis.AspNet.Identity.IIdentityUser 
    {
        public string SandataGUID { get; set; }
        public string GivenName { get; set; }
        public string RefreshToken { get; set; }
        public string AccessToken { get; set; }
        public string Org { get; set; }
        public string OrgUnit { get; set; }
        public string LastLogin { get; set; }

        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser> manager)
        {
            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            var userIdentity = await manager.CreateIdentityAsync(this, DefaultAuthenticationTypes.ApplicationCookie);
            // Add custom user claims here
            var user = this;
            if (!String.IsNullOrEmpty(OpenIDMUserContext.AccessToken))
            {
                userIdentity.AddClaim(new Claim("SandataGUID", OpenIDMUserContext.SandataGuid));
                if (string.IsNullOrEmpty(OpenIDMUserContext.CommonName) == false)
                {
                    userIdentity.AddClaim(new Claim("FullName", OpenIDMUserContext.CommonName));
                }
                userIdentity.AddClaim(new Claim("RefreshToken", OpenIDMUserContext.RefreshToken));
                userIdentity.AddClaim(new Claim("AccessToken", OpenIDMUserContext.AccessToken));
                userIdentity.AddClaim(new Claim("Org", OpenIDMUserContext.Organization));
                if (string.IsNullOrEmpty(OpenIDMUserContext.RawPersona) == false)
                {
                    userIdentity.AddClaim(new Claim("Persona", OpenIDMUserContext.RawPersona));
                }
                if (string.IsNullOrEmpty(OpenIDMUserContext.OrganUnit) == false)
                {
                    userIdentity.AddClaim(new Claim("OrgUnit", OpenIDMUserContext.OrganUnit));
                }
                if (string.IsNullOrEmpty(OpenIDMUserContext.LastLogin) == false)
                {
                    userIdentity.AddClaim(new Claim("LastLogin", OpenIDMUserContext.LastLogin));
                }
            }
            return userIdentity;
        }
    }

    public class SlapRedisConn
    {
        public static ConnectionMultiplexer Rdis = ConnectionMultiplexer.Connect(ConfigurationManager.AppSettings["SanRdConn"]);

        public static ConnectionMultiplexer rdis
        {
            get
            {
                return Rdis;
            }
        }
    }

    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext()
            : base("DefaultConnection", throwIfV1Schema: false)
        {
        }

        public static ApplicationDbContext Create()
        {
            return new ApplicationDbContext();
        }
    }
}