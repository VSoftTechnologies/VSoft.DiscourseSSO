/*
' Copyright (c) 2018 Vincent Parrett
'  All rights reserved.
' 
' THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
' TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
' THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
' CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
' DEALINGS IN THE SOFTWARE.
' 
*/

using DotNetNuke.Web.Mvc.Framework.ActionFilters;
using DotNetNuke.Web.Mvc.Framework.Controllers;
using System;
using System.Collections.Specialized;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Configuration;
using System.Web.Mvc;

namespace VSoft.DiscourseSSO.Controllers
{
	[DnnHandleError]
	public class SSOAuthController : DnnController
	{
		private static string GetPayloadSig(string ssoPayload, string ssoSecret)
		{
			var encoding = new UTF8Encoding();
			var secretBytes = encoding.GetBytes(ssoSecret);

			HMACSHA256 hmacHasher = new HMACSHA256(secretBytes);

			var payloadBytes = encoding.GetBytes(ssoPayload);
			var payloadHash = hmacHasher.ComputeHash(payloadBytes);


			string result = string.Empty;
			foreach (byte x in payloadHash)
				result += $"{x:x2}";
			return result;
		}


		public ActionResult Index()
		{
			string error = "getting query strings";
			try
			{
				var sso = Request.QueryString["sso"];
				var sig = Request.QueryString["sig"];

				if (string.IsNullOrEmpty(sig))
					return View();

				if (string.IsNullOrEmpty(sso) || string.IsNullOrEmpty(sig))
					throw new Exception("SSO or SIG can not be empty");

				error = "getting config settings";
				string ssoSecret = WebConfigurationManager.AppSettings["ssoSecret"];
				if (string.IsNullOrEmpty(ssoSecret))
					throw new Exception("ssoSecret not set in web.config");
				string ssoDiscourseUrl = WebConfigurationManager.AppSettings["ssoDiscourseUrl"];
				if (string.IsNullOrEmpty(ssoDiscourseUrl))
					throw new Exception("ssoDiscourseUrl not set in web.config");


				error = "getting payload sig";
				string payloadSig = GetPayloadSig(sso, ssoSecret);
				if (payloadSig != sig)

					//return Content($"<p>Check sum of SSO is different from SIG<br/> original : {originalsso} <br/> sso : {sso} <br/> sig : {sig} <br/> checksum {checksum}", "text/html");
					throw new Exception($"<p>Check sum of SSO is different from SIG \n sso : {sso} \n sig : {sig} \n checksum {payloadSig} \n request {Request.RawUrl}");


				error = "getting payload bytes";
				byte[] ssoBytes = Convert.FromBase64String(sso);
				error = "decoding payload";
				string decodedPayload = Encoding.UTF8.GetString(ssoBytes);

				error = "parsing payload into nvc";
				NameValueCollection nvc = HttpUtility.ParseQueryString(decodedPayload);

				error = "getting nonce";
				string nonce = nvc["nonce"];
				error = "getting user details";

				string email = User.Email;
				string username = User.Username;
				string name = User.DisplayName;
				string externalId = User.UserID.ToString();

				bool isAdmin = User.IsInRole("ForumsAdmin");
				bool isModerator = User.IsInRole("ForumsModerator");

				error = "building return payload";

				string returnPayload = "nonce=" + HttpUtility.UrlEncode(nonce) + "&email=" + HttpUtility.UrlEncode(email) +
										"&external_id=" + HttpUtility.UrlEncode(externalId) +
										"&username=" + HttpUtility.UrlEncode(username) +
										"&name=" + HttpUtility.UrlEncode(name) +
										"&admin=" + isAdmin.ToString().ToLower() +
										"&moderator=" + isModerator.ToString().ToLower();

				error = "encoding return payload";

				string encodedPayload = Convert.ToBase64String(Encoding.UTF8.GetBytes(returnPayload));
				error = "calculating return payload sig";

				string returnSig = GetPayloadSig(encodedPayload, ssoSecret);

				ssoDiscourseUrl += "/session/sso_login?sso=" + encodedPayload + "&sig=" + returnSig;

				error = "returning redirect";
				return new RedirectResult(ssoDiscourseUrl);
			}
			catch (Exception ex)
			{
				return new HttpStatusCodeResult(HttpStatusCode.InternalServerError, "There is error in SSO module " + ex.Message + " \n" + error);
			}
		}
	}
}
