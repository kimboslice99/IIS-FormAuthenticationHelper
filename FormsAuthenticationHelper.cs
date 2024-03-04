using System;
using System.Diagnostics;
using System.Linq;
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
#if DEBUG
                WriteDbg("FormsAuthenticationModule missing");
#endif
                throw new InvalidOperationException("FormsAuthenticationModule is not loaded.");
            }
            context.AuthenticateRequest += new EventHandler(Login);
            context.EndRequest += new EventHandler(Logout);
        }

        public void Login(Object source, EventArgs e)
        {
            HttpApplication app = (HttpApplication)source;
            HttpRequest request = app.Context.Request;
            
            if (request.HttpMethod == "POST" && request.Url.AbsolutePath.ToLower() == FormsAuthentication.LoginUrl.ToLower())
            {
#if DEBUG
                WriteDbg($"Login() Validating user:[{request.Form.Get("username")}]");
#endif
                if (Membership.ValidateUser(request.Form.Get("username"), request.Form.Get("password")))
                {
                    FormsAuthentication.RedirectFromLoginPage(request.Form.Get("username"), false);
                    WriteLog($"Membership.ValidateUser() success user:[{request.Form.Get("username")}] ip:[{request.ServerVariables["REMOTE_ADDR"]}] path:[{request.Url.AbsolutePath}]", EventLogEntryType.Information);
                }
                else
                {
                    WriteLog($"Membership.ValidateUser() failure user:[{request.Form.Get("username")}] ip:[{request.ServerVariables["REMOTE_ADDR"]}] path:[{request.Url.AbsolutePath}]", EventLogEntryType.Warning);
                }
            }
        }

        public void Logout(Object source, EventArgs e)
        {
            HttpApplication app = (HttpApplication)source;
            HttpResponse response = app.Context.Response;

            // we can use server side scripting to log the user out, ie
            // <?php header('X-Logout-User: logout');
            if (response.Headers.AllKeys.Contains("X-Logout-User"))
            {
                response.Headers.Remove("X-Logout-User");
                FormsAuthentication.SignOut();
                response.Redirect(FormsAuthentication.LoginUrl);
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
#if DEBUG
        private void WriteDbg(string msg)
        {
            System.Diagnostics.Debug.WriteLine($"[FormsAuthenticationHelper]: {msg}");
        }
#endif
    }
}
