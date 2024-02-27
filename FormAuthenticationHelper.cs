using System;
using System.Configuration;
using System.Data.Odbc;
using System.Diagnostics;
using System.Linq;
using System.Linq.Expressions;
using System.Web;
using System.Web.Security;
using Microsoft.Web.Administration;


namespace FormAuthenticationHelper
{
    public class FormAuthenticationHelper : IHttpModule
    {
        public void Dispose() {  }


        public void Init(HttpApplication context)
        {
            context.AuthenticateRequest += new EventHandler(Login);
            context.AuthorizeRequest += new EventHandler(Authorize);
        }

        public void Authorize(Object source, EventArgs e)
        {
            HttpApplication app = (HttpApplication)source;
            HttpRequest request = app.Context.Request;
            HttpResponse response = app.Context.Response;

            if (!IsModuleLoaded(typeof(System.Web.Security.FormsAuthenticationModule)))
            {
                DbgWrite("Form Auth Module missing");
                return;
            }

            if (!request.Url.AbsolutePath.ToLower().EndsWith(FormsAuthentication.LoginUrl.ToLower()))
                if (!request.IsAuthenticated)
                {
                    // Redirect to login page if the user is not authenticated
                    FormsAuthentication.RedirectToLoginPage();
                }

            if (!ValidateUserGroup(app.Context.User.Identity.Name))
            {
                DbgWrite("denied usergroup " + app.Context.User.Identity.Name);
                response.StatusCode = 401;
            }
        }

        public void Login(Object source, EventArgs e)
        {
            HttpApplication app = (HttpApplication)source;
            HttpRequest request = app.Context.Request;
            HttpResponse response = app.Context.Response;

            if (!IsModuleLoaded(typeof(System.Web.Security.FormsAuthenticationModule)))
            {
                DbgWrite("Form Auth Module missing");
                return;
            }

            // we should only respond to post requests at our loginurl
            if (request.HttpMethod != "POST" && request.Url.AbsolutePath.ToLower() != FormsAuthentication.LoginUrl.ToLower())
            {
                return;
            }

            if(ValidateUserCredentials(request.Form.Get("username"), request.Form.Get("password")))
            {
                DbgWrite("validated user " + request.Form.Get("username"));
                FormsAuthentication.RedirectFromLoginPage(request.Form.Get("username"), false);
            }
        }


        /// <summary>
        /// Validate a users credentials
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="passWord"></param>
        /// <returns></returns>
        private bool ValidateUserGroup(string userName)
        {
            string ODBC;
            ODBC = TryGetConnectionString();

            string UserGroups = ConfigurationManager.AppSettings["Allowed_Groups"] ?? "";
            string[] UserGroupsArray = UserGroups.Split(',');

            if (string.IsNullOrEmpty(ODBC))
            {
                return true;
            }

            try
            {
                using (OdbcConnection conn = new OdbcConnection(ODBC))
                {
                    conn.Open();
                    using (OdbcCommand cmd = new OdbcCommand("Select `group` from users where `user` = ?", conn))
                    {
                        cmd.Parameters.Add("@user", OdbcType.VarChar).Value = userName;

                        var group = cmd.ExecuteScalar();
                        // is user a part of the groups allowed for the path?
                        // if user has no group listed, assume they have global permission
                        // conversely, if no group is listed for the path, assume anyone logged in is permitted to access
                        if ((UserGroupsArray.Contains(group) || string.IsNullOrEmpty(UserGroups)))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Add error handling here for debugging.
                // This error message should not be sent back to the caller.
                DbgWrite("Exception " + ex.Message);
            }
            return false;
        }

        /// <summary>
        /// Validate a users credentials
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="passWord"></param>
        /// <returns></returns>
        private bool ValidateUserCredentials(string userName, string password)
        {
            string passwordLookup = null;

            string ODBC;
            try
            {
                ODBC = ConfigurationManager.ConnectionStrings["FormAuthentication"].ConnectionString;
            }
            catch
            {
                ODBC = "";
            }

            string UserGroups = ConfigurationManager.AppSettings["Allowed_Groups"] ?? "";
            string[] UserGroupsArray = UserGroups.Split(',');

            if (string.IsNullOrEmpty(ODBC))
            {
                return true;
            }

            if (string.IsNullOrEmpty(userName) || userName.Length > 100)
            {
                DbgWrite("Input validation of userName failed.");
                return false;
            }

            if (string.IsNullOrEmpty(password) || password.Length > 128)
            {
                DbgWrite("Input validation of password failed.");
                return false;
            }

            try
            {
                using (OdbcConnection conn = new OdbcConnection(ODBC))
                {
                    conn.Open();
                    using (OdbcCommand cmd = new OdbcCommand("Select `password` from users where `user` = ?", conn))
                    {
                        cmd.Parameters.Add("@user", OdbcType.VarChar).Value = userName;

                        passwordLookup = cmd.ExecuteScalar().ToString();
                        
                        // is user a part of the groups allowed for the path?
                        // if user has no group listed, assume they have global permission
                        // conversely, if no group is listed for the path, assume anyone logged in is permitted to access
                        if (passwordLookup == password)
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Add error handling here for debugging.
                // This error message should not be sent back to the caller.
                DbgWrite("Exception " + ex.Message);
            }
            return false;
        }

        public string TryGetConnectionString()
        {
            try
            {
                return ConfigurationManager.ConnectionStrings["FormAuthentication"].ConnectionString;
            }
            catch
            {
                return "";
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
