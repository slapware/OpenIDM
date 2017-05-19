using Microsoft.AspNet.Identity; 
using Microsoft.AspNet.Identity.EntityFramework; 
// NOTE: Added for Role management.
using Microsoft.AspNet.Identity.Owin; 
using Microsoft.Owin; 
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using ResiIdentity.Models;
using StackExchange.Redis;
using StackRedis.AspNet.Identity;

namespace ResiIdentity.Infrastructure
{

    public class ApplicationRoleManager : RoleManager<IdentityRole>
    {
        public ApplicationRoleManager(IRoleStore<IdentityRole, string> roleStore) 
             : base(roleStore) 
         { 
         } 
 
 
         public static ApplicationRoleManager Create(IdentityFactoryOptions<ApplicationRoleManager> options, IOwinContext context) 
         { 
             var appRoleManager = new ApplicationRoleManager(new RoleStore<IdentityRole>(context.Get<ApplicationDbContext>())); 
 
 
             return appRoleManager; 
         } 
    }
}