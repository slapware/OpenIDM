// For access to OpenAM to get and check token information
// and to obtain new token from refresh_token
// Modified 2/15/16 for static vars

namespace ResiIdentity.Models
{
    using System;
    using System.Collections.Generic;
    using System.Configuration;
    using System.Diagnostics;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Text;
    using System.Web;
    using System.Threading.Tasks; // Added to support Task for PATCH call
    using Newtonsoft.Json; // NOTE: this is an addition for change password
    using Newtonsoft.Json.Linq;

    #region OpenIDMUserContext
    public static class OpenIDMUserContext
    {
        /// <summary>
        ///     The list of groups for user
        /// </summary>
        public static List<string> GroupList;

        /// <summary>
        ///     The list of Persona for user
        /// </summary>
        public static List<string> PersonaList;

        static OpenIDMUserContext()
        {
            // NOTE: init values from web config for connection.
            GroupList = new List<string>();
            PersonaList = new List<string>();
            Realm = ConfigurationManager.AppSettings["Realm"];
            AuthorizationEndPoint = ConfigurationManager.AppSettings["AuthorizationEndPoint"];
            TokenEndpoint = ConfigurationManager.AppSettings["TokenEndpoint"];
            UserInfoEndpoint = ConfigurationManager.AppSettings["UserInfoEndpoint"];
            AgentId = ConfigurationManager.AppSettings["AgentID"];
            AgentSecret = ConfigurationManager.AppSettings["AgentKey"];
        }

        /// <summary>
        ///     Set the auth endpoint URI
        /// </summary>
        public static string AuthorizationEndPoint { get; set; }

        /// <summary>
        ///     Set theToken end point URI
        /// </summary>
        public static string TokenEndpoint { get; set; }

        /// <summary>
        ///     Set access_token
        /// </summary>
        public static string AccessToken { get; set; }

        /// <summary>
        ///     Set refresh_token
        /// </summary>
        public static string RefreshToken { get; set; }

        /// <summary>
        ///     Set the user info end point
        /// </summary>
        public static string UserInfoEndpoint { get; set; }

        /// <summary>
        ///     Gets or sets the Sandata supplied agent ID
        /// </summary>
        public static string AgentId { get; set; }

        /// <summary>
        ///     Gets or sets the Sandata Last Login time
        /// </summary>
        public static string LastLogin { get; set; }

        /// <summary>
        ///     Gets or sets the Sandata supplied user ID
        /// </summary>
        public static string UserId { get; set; }

        /// <summary>
        ///     Gets or sets the Sandata supplied user ID
        /// </summary>
        public static string UserSecret { get; set; }

        /// <summary>
        ///     Gets or sets the Organization
        /// </summary>
        public static string Organization { get; set; }

        /// <summary>
        ///     Gets or sets the Organization Unit
        /// </summary>
        public static string OrganUnit { get; set; }

        /// <summary>
        ///     Gets or sets the viewbag messagess
        /// </summary>
        public static string ViewMessage { get; set; }

        /// <summary>
        ///     Gets or sets the Common Name
        /// </summary>
        public static string CommonName { get; set; }

        /// <summary>
        ///     Gets or sets the Raw Groups
        /// </summary>
        public static string RawGroups { get; set; }

        /// <summary>
        ///     Gets or sets the Persona Groups
        /// </summary>
        public static string RawPersona { get; set; }

        /// <summary>
        ///     Gets or sets the SandataGUID
        /// </summary>
        public static string SandataGuid { get; set; }

        /// <summary>
        ///     Gets or sets the Sandata supplied agent Secret
        /// </summary>
        public static string AgentSecret { get; set; }

        /// <summary>
        ///     Gets or sets the Sandata userinfo
        /// </summary>
        public static string UserJson { get; set; }

        /// <summary>
        ///     Gets or sets the Auth Realm
        /// </summary>
        public static string Realm { get; set; }

        /// <summary>
        ///     Gets or sets the Auth Realm
        /// </summary>
        public static string SandataAccess { get; set; }

        /// <summary>
        ///     Get the user information from openam for claims and groups.
        /// </summary>
        /// <param name="sanuser"></param>
        /// <param name="sanpass"></param>
        /// <returns></returns>
        public static bool Find(string sanuser, string sanpass)
        {
            UserId = sanuser;
            UserSecret = sanpass;
            var scope = "SandataGUID isMemberOf email o ou cn lastLoginTime SandataAccess Persona";

            var requestBody = "grant_type=password&username=" + UserId + "&password=" + UserSecret + "&scope="
                              + Uri.EscapeDataString(scope);
            var httpClient = new HttpClient();
            var requestMessage = new HttpRequestMessage(HttpMethod.Post, TokenEndpoint + Realm);
            requestMessage.Headers.Add(
                "Authorization",
                "Basic "
                + Convert.ToBase64String(
                    Encoding.ASCII.GetBytes(string.Format("{0}:{1}", AgentId, AgentSecret))));
            requestMessage.Content = new StringContent(requestBody, Encoding.UTF8, "application/x-www-form-urlencoded");
            var tokenResponse = httpClient.SendAsync(requestMessage);
            var content = tokenResponse.Result.Content.ReadAsStringAsync();
            var tokeninfo = content.Result;
            if (tokeninfo.Contains("error") || string.IsNullOrEmpty(tokeninfo))
            {
                bool ans = IsLocked(sanuser);
                return false;
            }
            var myauth = JObject.Parse(tokeninfo);
            JToken value;
            AccessToken = myauth.TryGetValue("access_token", out value) ? value.ToString() : null;
            RefreshToken = myauth.TryGetValue("refresh_token", out value) ? value.ToString() : null;
            if (AccessToken != null)
            {
                var userquery = UserInfoEndpoint + Realm + "&access_token="
                                + Uri.EscapeDataString(AccessToken);
                var infoMessage = new HttpRequestMessage(HttpMethod.Get, userquery);
                var infoResponce = httpClient.SendAsync(infoMessage);
                var userinfo2 = infoResponce.Result.Content.ReadAsStringAsync();
                var sinfo = userinfo2.Result;
                var sanInfo = JObject.Parse(sinfo);
                SandataGuid = sanInfo.TryGetValue("SandataGUID", out value) ? value.ToString() : null;
                OrganUnit = sanInfo.TryGetValue("ou", out value) ? value.ToString() : null;
                Organization = sanInfo.TryGetValue("o", out value) ? value.ToString() : null;
                CommonName = sanInfo.TryGetValue("cn", out value) ? value.ToString() : null;
                RawGroups = sanInfo.TryGetValue("isMemberOf", out value) ? value.ToString() : null;
                RawPersona = sanInfo.TryGetValue("Persona", out value) ? value.ToString() : null;
                LastLogin = sanInfo.TryGetValue("lastLoginTime", out value) ? value.ToString() : null;
                SandataAccess = sanInfo.TryGetValue("SandataAccess", out value) ? value.ToString() : null;
            }
            return true;
        }
        /// <summary>
        /// Check if the access token is valid
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public static bool CheckToken(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                return false;
            }
            var userquery = UserInfoEndpoint + Realm + "&access_token=" + Uri.EscapeDataString(token);
            var infoMessage = new HttpRequestMessage(HttpMethod.Get, userquery);
            var httpClient = new HttpClient();
            var infoResponce = httpClient.SendAsync(infoMessage);
            var userinfo2 = infoResponce.Result.Content.ReadAsStringAsync();
            var tokeninfo = userinfo2.Result;
            if (tokeninfo.Contains("Access Token not valid") || string.IsNullOrEmpty(tokeninfo))
            {
                return false;
            }
            // token is valid so all is well
            return true;
        }

        // Get new accesss_token and refresh_token using refresh token if valdid
        public static string GetNewToken(string refreshToken)
        {
            var newtoken = "";
            if (string.IsNullOrEmpty(refreshToken))
            {
                newtoken = "error";
                return newtoken;
            }
            var requestBody = "grant_type=refresh_token&refresh_token=" + Uri.EscapeDataString(refreshToken);
            var httpClient = new HttpClient();
            var requestMessage = new HttpRequestMessage(HttpMethod.Post, TokenEndpoint + Realm);
            requestMessage.Headers.Add(
                "Authorization",
                "Basic "
                + Convert.ToBase64String(
                    Encoding.ASCII.GetBytes(string.Format("{0}:{1}", AgentId, AgentSecret))));
            requestMessage.Content = new StringContent(requestBody, Encoding.UTF8, "application/x-www-form-urlencoded");
            var tokenResponse = httpClient.SendAsync(requestMessage);
            var content = tokenResponse.Result.Content.ReadAsStringAsync();
            var tokeninfo = content.Result;
            if (tokeninfo.Contains("error") || string.IsNullOrEmpty(tokeninfo))
            {
                newtoken = "error";
                return newtoken;
            }
            var myauth = JObject.Parse(tokeninfo);
            JToken value;
            AccessToken = myauth.TryGetValue("access_token", out value) ? value.ToString() : null;
            RefreshToken = myauth.TryGetValue("refresh_token", out value) ? value.ToString() : null;

            return RefreshToken;
        }

        /// <summary>
        ///     Parse the raw text in JSON for group names for user.
        /// </summary>
        public static void ParseGroups()
        {
            if(GroupList.Count > 0)
                GroupList.Clear();
            string[] stringSeparators = { "cn=", "," };
            var words = RawGroups.Split(stringSeparators, StringSplitOptions.RemoveEmptyEntries);
            foreach (var entry in words)
            {
                if (!entry.Contains("="))
                {
                    GroupList.Add(entry);
                }
            }
        }

        /// <summary>
        ///     Parse the raw text in JSON for persona names for user.
        /// </summary>
        public static void ParsePersona()
        {
            if (PersonaList.Count > 0)
                PersonaList.Clear();
            string[] stringSeparators = { "," };
            var words = RawPersona.Split(stringSeparators, StringSplitOptions.RemoveEmptyEntries);
            foreach (var entry in words)
            {
                if (!String.IsNullOrEmpty(entry))
                {
                    PersonaList.Add(entry);
                }
            }
        }

        public static async Task<bool> AddPersona(string sanuser, string newPersona)
        {
            string iuri = ConfigurationManager.AppSettings["IdmUri"] + sanuser;
            string idmhost = ConfigurationManager.AppSettings["IdmUri"];
            int idmport = Convert.ToInt32(ConfigurationManager.AppSettings["IdmPort"]);
            string Idmscheme = ConfigurationManager.AppSettings["IdmScheme"];
            string idmU = ConfigurationManager.AppSettings["Idmu"];
            string idmP = ConfigurationManager.AppSettings["Idmp"];

            UriBuilder userUri = new UriBuilder(Idmscheme, idmhost, idmport, "openidm/managed/user/" + sanuser);

            Dictionary<string, string> userPswd = new Dictionary<string, string>
                                                      {
                                                          { "operation", "add" },
                                                          { "field", "Persona/-" },
                                                          { "value", newPersona }
                                                      };
            string pswdjson = JsonConvert.SerializeObject(userPswd, Formatting.Indented);
            string pswdata = "[" + pswdjson + "]";
            var httpClient = new HttpClient();
            var responseMessage = await httpClient.PatchAsync(userUri.Uri, pswdata, sanuser);
            if (!responseMessage)
            {
                ViewMessage = @"Persona not added.";
                return false;
            }
            ViewMessage = @"Persona added.";
            return true;
        }

        public static async Task<bool> RemovePersona(string sanuser, string newPersona)
        {
            string iuri = ConfigurationManager.AppSettings["IdmUri"] + sanuser;
            string idmhost = ConfigurationManager.AppSettings["IdmUri"];
            int idmport = Convert.ToInt32(ConfigurationManager.AppSettings["IdmPort"]);
            string Idmscheme = ConfigurationManager.AppSettings["IdmScheme"];
            string idmU = ConfigurationManager.AppSettings["Idmu"];
            string idmP = ConfigurationManager.AppSettings["Idmp"];

            UriBuilder userUri = new UriBuilder(Idmscheme, idmhost, idmport, "openidm/managed/user/" + sanuser);

            Dictionary<string, string> userPswd = new Dictionary<string, string>
                                                      {
                                                          { "operation", "remove" },
                                                          { "field", "/Persona" },
                                                          { "value", newPersona }
                                                      };
            string pswdjson = JsonConvert.SerializeObject(userPswd, Formatting.Indented);
            string pswdata = "[" + pswdjson + "]";
            var httpClient = new HttpClient();
            var responseMessage = await httpClient.PatchAsync(userUri.Uri, pswdata, sanuser);
            if (!responseMessage)
            {
                ViewMessage = @"Persona not removed.";
                return false;
            }
            ViewMessage = @"Persona removed.";
            return true;
        }

        /// <summary>
        /// This is new function to change flag and update password in LDAP
        /// and return last password changed date to confirm change.
        /// </summary>
        /// <param name="sanuser"></param>
        /// <param name="newPassword"></param>
        /// <returns></returns>
        public static async Task<bool> ChangePassword(string sanuser, string newPassword)
        {
            string iuri = ConfigurationManager.AppSettings["IdmUri"] + sanuser;
            string idmhost = ConfigurationManager.AppSettings["IdmUri"];
            int idmport = Convert.ToInt32(ConfigurationManager.AppSettings["IdmPort"]);
            string Idmscheme = ConfigurationManager.AppSettings["IdmScheme"];
            string idmU = ConfigurationManager.AppSettings["Idmu"];
            string idmP = ConfigurationManager.AppSettings["Idmp"];

            UriBuilder userUri = new UriBuilder(Idmscheme, idmhost, idmport, "openidm/managed/user/" + sanuser);

            Dictionary<string, string> userPswd = new Dictionary<string, string>
            {
               { "operation", "replace" },
               { "field", "/password" },
               { "value", newPassword }
            };
            string pswdjson = JsonConvert.SerializeObject(userPswd, Formatting.Indented);
            string pswdata = "[" + pswdjson + "]";
            var httpClient = new HttpClient();
            var responseMessage = await httpClient.PatchAsync(userUri.Uri, pswdata, sanuser);
            if (!responseMessage)
            {
                ViewMessage = @"Email not found or Invalid.";
                return false;
            }
            // *************** Check if the password has really been changed *********************************.
            // Allow 1 second for sync of update OpenIDM data
            await Task.Delay(1250);
            UriBuilder checkUri = new UriBuilder(Idmscheme, idmhost, idmport, "openidm/managed/user/" + sanuser);

            var query = HttpUtility.ParseQueryString(checkUri.Query);
            query["_fields"] = "pwdChangedTime";
            checkUri.Query = query.ToString();
            string checkcall = checkUri.ToString();

            var requestMessage = new HttpRequestMessage(HttpMethod.Get, checkcall);
            requestMessage.Headers.Add(
                "Authorization",
                "Basic "
                + Convert.ToBase64String(
                    Encoding.ASCII.GetBytes(string.Format("{0}:{1}", idmU, idmP))));
            var checkResponse = httpClient.SendAsync(requestMessage);
            var retdata = await checkResponse.Result.Content.ReadAsStringAsync();

            var mylock = JObject.Parse(retdata);
            JToken value;
            string isChanged = mylock.TryGetValue("pwdChangedTime", out value) ? value.ToString() : null;
            if (string.IsNullOrEmpty(isChanged))
            {
                ViewMessage = @"Password has Not been changed, Invalid or already used.";
            }
            else
            {
                string cyear = isChanged.Substring(0, 4);
                string cmonth = isChanged.Substring(4, 2);
                string cday = isChanged.Substring(6, 2);
                string chour = isChanged.Substring(8, 2);
                string cmin = isChanged.Substring(10, 2);
                int ichour = Int32.Parse(chour);
                int nhour = Int32.Parse(chour) - 4;
                DateTime dvalue = new DateTime(Int32.Parse(cyear), Int32.Parse(cmonth), Int32.Parse(cday), nhour,  Int32.Parse(cmin), 0);
                if (dvalue.Subtract(DateTime.Today).Days != 0)
                {
                    ViewMessage = @"Password was not changed";
                }
                else
                {
                    ViewMessage = @"Password was changed on " + dvalue;
                }
            } 
            var response = await httpClient.GetAsync(checkUri.Uri);

            //will throw an exception if not successful
            response.EnsureSuccessStatusCode();

            string content = await response.Content.ReadAsStringAsync();

            // *************** Change SandataAccess to yes to flag as done with password change *******************.
            Dictionary<string, string> sanAccess = new Dictionary<string, string>
            {
               { "operation", "replace" },
               { "field", "/SandataAccess" },
               { "value", "YES" }
            };
            string ascjson = JsonConvert.SerializeObject(sanAccess, Formatting.Indented);
            string ascdata = "[" + ascjson + "]";
            var responseMessage2 = await httpClient.PatchAsync(userUri.Uri, ascdata, sanuser);

            return (responseMessage & responseMessage2) ? true : false;
        }

        /// <summary>
        /// This is new function to check if locked out of LDAP
        /// which will require a password change to clear lockout..
        /// </summary>
        /// <param name="sanuser"></param>
        /// <returns></returns>
        public static bool IsLocked(string sanuser)
        {
            string iuri = ConfigurationManager.AppSettings["IdmUri"] + sanuser;
            string idmhost = ConfigurationManager.AppSettings["IdmUri"];
            int idmport = Convert.ToInt32(ConfigurationManager.AppSettings["IdmPort"]);
            string Idmscheme = ConfigurationManager.AppSettings["IdmScheme"];
            string idmU = ConfigurationManager.AppSettings["Idmu"];
            string idmP = ConfigurationManager.AppSettings["Idmp"];
            // Delay 1 second to allow sync update of OpenIDM data
            System.Threading.Thread.Sleep(1250);
            UriBuilder userUri = new UriBuilder(Idmscheme, idmhost, idmport, "openidm/managed/user/" + sanuser);
            var httpClient = new HttpClient();
  
            var query = HttpUtility.ParseQueryString(userUri.Query);
            query["_fields"] = "pwdAccountLockedTime";
            userUri.Query = query.ToString();
            string lockcall = userUri.ToString(); 

             var requestMessage = new HttpRequestMessage(HttpMethod.Get, lockcall);
             requestMessage.Headers.Add(
                 "Authorization",
                 "Basic "
                 + Convert.ToBase64String(
                     Encoding.ASCII.GetBytes(string.Format("{0}:{1}", idmU, idmP))));
             var lockResponse = httpClient.SendAsync(requestMessage);
             var content = lockResponse.Result.Content.ReadAsStringAsync();
             lockResponse.Wait();
             var retdata = content.Result;

             var mylock = JObject.Parse(retdata);
             JToken value;
             string isLocked = mylock.TryGetValue("pwdAccountLockedTime", out value) ? value.ToString() : null;
             if (string.IsNullOrEmpty(isLocked))
             {
                 ViewMessage = @"Account is not locked, invalid login";
                 return false;
             }
             else
             {
                 ViewMessage = @"Account is locked, Please request Password change";
                 return true;
             }
         }

        public static async Task<bool> EmailPassword(string sanuser, string newPassword)
        {
            string iuri = ConfigurationManager.AppSettings["IdmUri"] + sanuser;
            string idmhost = ConfigurationManager.AppSettings["IdmUri"];
            int idmport = Convert.ToInt32(ConfigurationManager.AppSettings["IdmPort"]);
            string Idmscheme = ConfigurationManager.AppSettings["IdmScheme"];
            string idmU = ConfigurationManager.AppSettings["Idmu"];
            string idmP = ConfigurationManager.AppSettings["Idmp"];

            UriBuilder emailUri = new UriBuilder(Idmscheme, idmhost, idmport, "openidm/external/email");
            var query = HttpUtility.ParseQueryString(emailUri.Query);
            query["_action"] = "send";
            emailUri.Query = query.ToString();
            string message = "Your tempoary password is " + newPassword + " please login and change, 8 char min length one capital and one number required.";
            var httpClient = new HttpClient();
            Dictionary<string, string> sanNotice = new Dictionary<string, string>
            {
               { "from", "no-reply@sandata.com" },
               { "to", sanuser },
               { "subject", "Password Reset" },
               { "body", message }
            };
            string mailjson = JsonConvert.SerializeObject(sanNotice, Formatting.Indented);
            string mailenc = HttpUtility.UrlEncode(mailjson);
            var responseMessage = await httpClient.DoPost(emailUri.Uri, mailjson, sanuser);
            return (responseMessage) ? true : false;
        }

        public static async Task<bool> ForgotPassword(string userId)
        {
            string npass = await GeneratePassword(4, 2, 2);
            bool isChanged = await ChangePassword(userId, npass);
            if (!isChanged)
            {
                return false;
            }
            bool isMailedd = await EmailPassword(userId, npass);
            while (!isMailedd)
            {
                isMailedd = await EmailPassword(userId, npass);
            }
            return true;
        }
        /// <summary>
        /// Generate random password for user that meets length - 8 and 1 upper and 1 numeric
        /// </summary>
        /// <param name="lowercase"></param>
        /// <param name="uppercase"></param>
        /// <param name="numerics"></param>
        /// <returns></returns>
        public static async Task<string> GeneratePassword(int lowercase, int uppercase, int numerics)
        {
            string lowers = "abcdefghi.jklmnopqrstuvwxyz";
            string uppers = "ABCDEFGHIJKLMN.OPQRSTUVWXYZ";
            string number = "0123456789";

            Random random = new Random();

            string generated = "!";
            for (int i = 1; i <= lowercase; i++)
                generated = generated.Insert(
                    random.Next(generated.Length),
                    lowers[random.Next(lowers.Length - 1)].ToString()
                );

            for (int i = 1; i <= uppercase; i++)
                generated = generated.Insert(
                    random.Next(generated.Length),
                    uppers[random.Next(uppers.Length - 1)].ToString()
                );

            for (int i = 1; i <= numerics; i++)
                generated = generated.Insert(
                    random.Next(generated.Length),
                    number[random.Next(number.Length - 1)].ToString()
                );

            return generated.Replace("!", string.Empty);
        }

    } // class OpenIDMUserContext
    #endregion OpenIDMUserContext

    #region extension-method
    /// <summary>
    /// Added Extension to allow PATCH on POST
    /// </summary>
    public static class HttpClientExtensions
    {
        /// <summary>
        /// Patch with basic auth for json content.
        /// </summary>
        /// <param name="client"></param>
        /// <param name="requestUri"></param>
        /// <param name="iContent"></param>
        /// <param name="username"></param>
        /// <returns></returns>
        public static async Task<bool> PatchAsync(this HttpClient client, Uri requestUri, string iContent, string username)
        {
            var method = new HttpMethod("PATCH");
            var request = new HttpRequestMessage(method, requestUri);
            request.Headers.Add(
                "Authorization",
                "Basic "
                + Convert.ToBase64String(
                    Encoding.ASCII.GetBytes(string.Format("{0}:{1}", ConfigurationManager.AppSettings["Idmu"], ConfigurationManager.AppSettings["Idmp"]))));
            request.Headers.Add("If-Match", "*");
            request.Content = new StringContent(iContent, Encoding.UTF8, "application/json");

            HttpResponseMessage response = new HttpResponseMessage();
            try
            {
                response = await client.SendAsync(request);
            }
            catch (TaskCanceledException e)
            {
                Debug.WriteLine("ERROR: " + e.ToString());
            }

            return response.IsSuccessStatusCode == true ? true : false;
        }
        /// <summary>
        /// POST with basuc auth and no if-match
        /// </summary>
        /// <param name="client"></param>
        /// <param name="requestUri"></param>
        /// <param name="iContent"></param>
        /// <param name="username"></param>
        /// <returns></returns>
        public static async Task<bool> DoPost(this HttpClient client, Uri requestUri, string iContent, string username)
        {
            var method = new HttpMethod("POST");
            var request = new HttpRequestMessage(method, requestUri);
            request.Headers.Add(
                "Authorization",
                "Basic "
                + Convert.ToBase64String(
                    Encoding.ASCII.GetBytes(string.Format("{0}:{1}", ConfigurationManager.AppSettings["Idmu"], ConfigurationManager.AppSettings["Idmp"]))));
            request.Content = new StringContent(iContent, Encoding.UTF8, "application/json");

            HttpResponseMessage response = new HttpResponseMessage();
            try
            {
                response = await client.SendAsync(request);
            }
            catch (TaskCanceledException e)
            {
                Debug.WriteLine("ERROR: " + e.ToString());
            }

            return response.IsSuccessStatusCode == true ? true : false;
        }

    }
    #endregion extension-method
}