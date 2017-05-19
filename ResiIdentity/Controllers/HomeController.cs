using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
// NOTE: added for [OpenIDMAuthAttribute]
using ResiIdentity.CustomAttributes;
using System.Security.Claims;
using System.Threading;

namespace ResiIdentity.Controllers
{

    public class HomeController : Controller
    {

        public  bool CheckGroup(string groupname)
        {
            bool ismember = false;
            var identity = (ClaimsIdentity)this.User.Identity;
            IEnumerable<Claim> claims = identity.Claims;
            foreach (var r in claims)
            {
                string cs = r.ToString();
                ismember = cs.Contains(groupname);
                if (ismember) return true;
            }
            return ismember;
        }

        public ActionResult Index()
        {
            return View();
        }

        [OpenIDMAuthAttribute]
        public ActionResult About()
        {
            bool doallow = CheckGroup(@"SanAgencyMngt");
            // If true show SanAgencyMngt menu option. The names to check for are returned in tokeninfo call
            ViewBag.Message = "Your application description page.";

            return View();
        }

        [OpenIDMAuthAttribute]
        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}