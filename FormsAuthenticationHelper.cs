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
            // check for the formauthenticationmodule to be loaded
            if (!IsModuleLoaded(typeof(System.Web.Security.FormsAuthenticationModule)))
            {
                WriteLog("FormsAuthenticationModule missing", EventLogEntryType.Error);
                WriteDbg("FormsAuthenticationModule missing");
                throw new InvalidOperationException("FormsAuthenticationModule is not loaded.");
            }
            // authenticate the user
            context.AuthenticateRequest += new EventHandler(Login);
            // update user last active
            context.AuthorizeRequest += new EventHandler(UpdateLastActive);
            // logout the user
            context.EndRequest += new EventHandler(Logout);
        }

        public void Login(Object source, EventArgs e)
        {
            HttpApplication app = (HttpApplication)source;
            HttpRequest request = app.Context.Request;
            
            if (request.HttpMethod == "POST" && AtLoginUrl(request))
            {
                // perform some validation
                string formUsername = request.Form.Get("username");
                string formPassword = request.Form.Get("password");
                // check if null or whitespace
                if (string.IsNullOrWhiteSpace(formUsername) || string.IsNullOrWhiteSpace(formPassword))
                {
                    WriteDbg($"Login() Validating user:[{formUsername}] failed. IsNullOrWhiteSpace()");
                    return;
                }
                // check more than 1000 chars
                if (formUsername.Length > 999 || formPassword.Length > 999)
                {
                    WriteDbg($"Login() Validating user:[{formUsername}] failed. string length limit exceeded.");
                    return;
                }

                if (Membership.ValidateUser(formUsername, formPassword))
                {
                    FormsAuthentication.RedirectFromLoginPage(formUsername, false);
                    WriteLog($"Membership.ValidateUser() success user:[{formUsername}] ip:[{request.ServerVariables["REMOTE_ADDR"]}] path:[{request.Url.AbsolutePath}]", EventLogEntryType.Information);
                }
                else
                {
                    WriteLog($"Membership.ValidateUser() failure user:[{formUsername}] ip:[{request.ServerVariables["REMOTE_ADDR"]}] path:[{request.Url.AbsolutePath}]", EventLogEntryType.Warning);
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
                //FormsAuthentication.RedirectToLoginPage(); // causes returnurl of logout page to
                response.Redirect(FormsAuthentication.LoginUrl);
            }
        }

        public void UpdateLastActive(Object source, EventArgs e)
        {
            HttpApplication app = (HttpApplication)source;
            HttpContext context = app.Context;
            if(IsAuthenticated(context))
            {
                Membership.GetUser(context.User.Identity.Name, true);
            }
        }

        internal bool AtLoginUrl(HttpRequest request)
        {
            return request.Url.AbsolutePath.ToLower() == FormsAuthentication.LoginUrl.ToLower();
        }

        internal bool IsAuthenticated(HttpContext context)
        {
            return context.User != null && context.User.Identity != null && context.User.Identity.IsAuthenticated;
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
#if DEBUG
            System.Diagnostics.Debug.WriteLine($"[FormsAuthenticationHelper]: {msg}");
#endif
        }
    }
}
