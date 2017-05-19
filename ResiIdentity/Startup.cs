using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(ResiIdentity.Startup))]
namespace ResiIdentity
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
