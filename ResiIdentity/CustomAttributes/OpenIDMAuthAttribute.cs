// NOTE: added for OpenIDMUserContext

// NOTE: create tag [OpenIDMAuthAttribute] to check and reissue token from OpenAM

namespace ResiIdentity.CustomAttributes
{
    using System.Security.Claims;
    using System.Web;
    using System.Web.Mvc;
    using System.Web.Mvc.Filters;

    using Microsoft.AspNet.Identity;
    using Microsoft.AspNet.Identity.Owin;
    using Microsoft.Owin.Security;

    using ResiIdentity.Models;

    public class OpenIDMAuthAttribute : ActionFilterAttribute, IAuthenticationFilter
    {
        public void OnAuthentication(AuthenticationContext filterContext)
        {
        }

        public void OnAuthenticationChallenge(AuthenticationChallengeContext filterContext)
        {
            var user = filterContext.HttpContext.User;
            if (user == null || !user.Identity.IsAuthenticated)
            {
                filterContext.Result = new HttpUnauthorizedResult();
            }
            var identity = (ClaimsIdentity)user.Identity;
            var accesstoken = identity.FindFirstValue("AccessToken");
            var refreshtoken = identity.FindFirstValue("RefreshToken");
            if (OpenIDMUserContext.CheckToken(accesstoken))
            {
                return;
            }
            var newdata = OpenIDMUserContext.GetNewToken(refreshtoken);
            if (newdata.Contains("error"))
            {
                filterContext.Result = new HttpUnauthorizedResult();
            }
            else
            {
                // NOTE: update the claims for token and refresh token
                var authenticationManager = HttpContext.Current.GetOwinContext().Authentication;
                var Identity = new ClaimsIdentity(user.Identity);
                Identity.RemoveClaim(Identity.FindFirst("AccessToken"));
                Identity.AddClaim(new Claim("AccessToken", OpenIDMUserContext.AccessToken));
                Identity.RemoveClaim(Identity.FindFirst("RefreshToken"));
                Identity.AddClaim(new Claim("RefreshToken", OpenIDMUserContext.RefreshToken));
                authenticationManager.AuthenticationResponseGrant =
                    new AuthenticationResponseGrant(
                        new ClaimsPrincipal(Identity),
                        new AuthenticationProperties { IsPersistent = true });
            }
        }
    }
}