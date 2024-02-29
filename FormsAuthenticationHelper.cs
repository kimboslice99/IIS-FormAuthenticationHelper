using System;
using System.Security.Principal;
using System.Web;
using System.Web.Security;


namespace FormsAuthenticationHelper
{
    public class FormsAuthenticationHelper : IHttpModule
    {
        public void Dispose() {  }


        public void Init(HttpApplication context)
        {
            if (!IsModuleLoaded(typeof(System.Web.Security.FormsAuthenticationModule)))
            {
                DbgWrite("Form Auth Module missing");
                throw new MissingMethodException();
            }
            context.AuthenticateRequest += new EventHandler(Login);
            context.AuthorizeRequest += new EventHandler(Authorize);
        }


        public void Authorize(Object source, EventArgs e)
        {
            HttpApplication app = (HttpApplication)source;
            HttpContext context = app.Context;
            HttpRequest request = context.Request;

            // Only check authoriation on urls which arent our loginurl
            if (request.Url.AbsolutePath.ToLower() != FormsAuthentication.LoginUrl.ToLower())
            {
                // Retrieve the current user's principal
                IPrincipal user = context.User;

                // If user is null then make it anonymous... I am surprised this isnt done on its own
                if (user == null)
                {
                    user = new GenericPrincipal(new GenericIdentity(""), null);
                }

                // Check URL access for the current user's principal
                if (!UrlAuthorizationModule.CheckUrlAccessForPrincipal(request.Url.AbsolutePath, user, request.HttpMethod))
                {
                    DbgWrite($"Access denied for user:[{user.Identity.Name}] at path:[{request.Path}]");
                    FormsAuthentication.RedirectToLoginPage();
                }
                else
                {
                    DbgWrite($"Allowed user:[{user.Identity.Name}] at path:[{request.Path}]");
                }
            }
        }

        public void Login(Object source, EventArgs e)
        {
            HttpApplication app = (HttpApplication)source;
            HttpRequest request = app.Context.Request;
            
            // we should only respond to post requests at our loginurl
            if (request.HttpMethod != "POST" && request.Url.AbsolutePath.ToLower() != FormsAuthentication.LoginUrl.ToLower())
            {
                DbgWrite("Login(): Not at path and request method is not post, return");
                return;
            }
            DbgWrite("Validating user");
            if(Membership.ValidateUser(request.Form.Get("username"), request.Form.Get("password")))
            {
                FormsAuthentication.RedirectFromLoginPage(request.Form.Get("username"), false);
                DbgWrite($"validated user:[{request.Form.Get("username")}]");
            }
            else
            {
                DbgWrite($"Membership.ValidateUser() failure user:[{request.Form.Get("username")}]");
            }
        }

        /// <summary>
        /// Checks if a module is loaded
        /// </summary>
        /// <param name="moduleType"></param>
        /// <returns></returns>
        private bool IsModuleLoaded(Type moduleType)
        {
            foreach (string moduleName in HttpContext.Current.ApplicationInstance.Modules.AllKeys)
            {
                IHttpModule module = HttpContext.Current.ApplicationInstance.Modules[moduleName] as IHttpModule;
                if (module != null && module.GetType() == moduleType)
                {
                    return true;
                }
            }
            return false;
        }

        public void DbgWrite(string msg)
        {
            System.Diagnostics.Debug.WriteLine($"[FormAuthenticationHelper]: {msg}");
        }

    }
}
