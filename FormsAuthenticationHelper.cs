using System;
using System.Diagnostics;
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
                WriteLog("FormsAuthenticationModule missing", EventLogEntryType.Error);
                WriteDbg("FormsAuthenticationModule missing");
                throw new InvalidOperationException("FormsAuthenticationModule is not loaded.");
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

                // if user null then anonymouse
                if (user == null)
                {
                    user = new GenericPrincipal(new GenericIdentity(""), null);
                }

                // Check URL access for the current user's principal
                if (!UrlAuthorizationModule.CheckUrlAccessForPrincipal(request.Url.AbsolutePath, user, request.HttpMethod))
                {
                    WriteDbg($"Access denied for user:[{user.Identity.Name}] at path:[{request.Path}]");
                    FormsAuthentication.RedirectToLoginPage();
                }
                else
                {
                    WriteDbg($"Allowed user:[{user.Identity.Name}] at path:[{request.Path}]");
                }
            }
        }

        public void Login(Object source, EventArgs e)
        {
            HttpApplication app = (HttpApplication)source;
            HttpRequest request = app.Context.Request;
            
            if (request.HttpMethod == "POST" && request.Url.AbsolutePath.ToLower() == FormsAuthentication.LoginUrl.ToLower())
            {
                WriteDbg($"Login() Validating user:[{request.Form.Get("username")}]");
                if (Membership.ValidateUser(request.Form.Get("username"), request.Form.Get("password")))
                {
                    FormsAuthentication.RedirectFromLoginPage(request.Form.Get("username"), false);
                    WriteLog($"validated user:[{request.Form.Get("username")}]", EventLogEntryType.Information);
                }
                else
                {
                    WriteLog($"Membership.ValidateUser() failure user:[{request.Form.Get("username")}] path:[{request.Url.AbsolutePath}] ip:[{request.ServerVariables["REMOTE_ADDR"]}]", EventLogEntryType.Warning);
                }
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

        private void WriteLog(string msg, EventLogEntryType type)
        {
            EventLog.WriteEntry(".NET Runtime", $"[FormsAuthenticationHelper]: {msg}", type, 1000);
        }
        private void WriteDbg(string msg)
        {
            System.Diagnostics.Debug.WriteLine($"[FormsAuthenticationHelper]: {msg}");
        }
    }
}
