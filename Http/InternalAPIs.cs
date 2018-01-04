#region Related components
using System;
using System.IO;
using System.Web;
using System.Threading.Tasks;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using WampSharp.V2;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;

using net.vieapps.Services.Base.AspNet;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class InternalAPIs
	{
		internal static async Task ProcessRequestAsync(HttpContext context)
		{

#if DEBUG || PROCESSLOGS
			await Base.AspNet.Global.WriteLogsAsync(Base.AspNet.Global.GetCorrelationID(context.Items), "Internal", $"Begin process [{context.Request.HttpMethod}]: {context.Request.Url.Scheme}://{context.Request.Url.Host + context.Request.RawUrl} ({context.Request.UserHostAddress})").ConfigureAwait(false);
#endif

			#region prepare the requesting information
			var request = new RequestInfo()
			{
				Session = context.GetSession(),
				Verb = context.Request.HttpMethod,
				ServiceName = string.IsNullOrWhiteSpace(context.Request.QueryString["service-name"]) ? "unknown" : context.Request.QueryString["service-name"],
				ObjectName = string.IsNullOrWhiteSpace(context.Request.QueryString["object-name"]) ? "unknown" : context.Request.QueryString["object-name"],
				Query = context.Request.QueryString.ToDictionary(),
				Header = context.Request.Headers.ToDictionary(),
				CorrelationID = Base.AspNet.Global.GetCorrelationID(context.Items)
			};

			bool isSessionProccessed = false, isSessionInitialized = false, isAccountProccessed = false, isActivationProccessed = false;

			if (request.ServiceName.IsEquals("users"))
			{
				if ("session".IsEquals(request.ObjectName))
				{
					isSessionProccessed = true;
					isSessionInitialized = request.Verb.IsEquals("GET");
				}
				else if ("account".IsEquals(request.ObjectName))
					isAccountProccessed = request.Verb.IsEquals("POST") || request.Verb.IsEquals("PUT");
				else if ("activate".IsEquals(request.ObjectName))
					isActivationProccessed = request.Verb.IsEquals("GET");
			}
			#endregion

			#region prepare token
			var accessToken = "";
			try
			{
				var isSpecialUser = request.Session.User.ID.Equals("") || request.Session.User.IsSystemAccount;
				var tokenIsRequired = isActivationProccessed
					? false
					: isSessionInitialized && isSpecialUser && !request.Query.ContainsKey("register")
						? false
						: true;

				var appToken = request.GetParameter("x-app-token");
				if (!string.IsNullOrWhiteSpace(appToken))
					accessToken = request.Session.ParseJSONWebToken(appToken);
				else if (tokenIsRequired)
					throw new InvalidSessionException("Session is invalid (JSON Web Token is not found)");

				if (tokenIsRequired)
				{
					if (!await InternalAPIs.CheckSessionExistAsync(request.Session).ConfigureAwait(false))
						throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");

					if (!isSessionInitialized || !(isSpecialUser && request.Query.ContainsKey("register")))
						await InternalAPIs.VerifySessionIntegrityAsync(request.Session, accessToken).ConfigureAwait(false);
				}
			}
			catch (Exception ex)
			{
#if DEBUG || PROCESSLOGS
				await Base.AspNet.Global.WriteLogsAsync(request.CorrelationID, "Internal", "Error occurred while preparing token", ex).ConfigureAwait(false);
#endif
				await Base.AspNet.Global.WriteLogsAsync(request.CorrelationID, "Security.Errors", "Error occurred while preparing token", ex).ConfigureAwait(false);
				context.ShowError(ex, request, false);
				return;
			}
			#endregion

			#region prepare others (principal, identity, body)
			context.User = new UserPrincipal(request.Session.User);
			if (string.IsNullOrWhiteSpace(request.Session.SessionID))
				request.Session.SessionID = UtilityService.NewUID;

			if (request.Verb.IsEquals("POST") || request.Verb.IsEquals("PUT"))
				using (var reader = new StreamReader(context.Request.InputStream, context.Request.ContentEncoding))
				{
					request.Body = await reader.ReadToEndAsync().ConfigureAwait(false);
				}

			else if (request.Verb.IsEquals("GET") && context.Request.QueryString["x-body"] != null)
				try
				{
					request.Body = context.Request.QueryString["x-body"].Url64Decode();
				}
				catch
				{
					request.Body = "";
				}
			#endregion

#if DEBUG || PROCESSLOGS
			await Base.AspNet.Global.WriteLogsAsync(request.CorrelationID, "Internal", $"Request:\r\n{request.ToJson().ToString(Formatting.Indented)}").ConfigureAwait(false);
#endif

			#region [extra] prepare information of an account
			if (isAccountProccessed)
				try
				{
					var requestBody = request.GetBodyExpando();
					if (requestBody == null)
						throw new InvalidSessionException("Request JSON is invalid (empty)");

					// verify captcha
					var captcha = requestBody.Get<string>("Captcha");
					if (!string.IsNullOrWhiteSpace(captcha))
					{
						try
						{
							captcha = captcha.Decrypt(Base.AspNet.Global.GenerateEncryptionKey(request.Session.SessionID), Base.AspNet.Global.GenerateEncryptionIV(request.Session.SessionID));
						}
						catch (Exception ex)
						{
							throw new InvalidSessionException("Request JSON is invalid (captcha is invalid)", ex);
						}

						try
						{
							var info = JObject.Parse(captcha);
							if (!Captcha.IsCodeValid((info["Registered"] as JValue).Value as string, (info["Input"] as JValue).Value as string))
								throw new InformationInvalidException("Captcha code is invalid");
						}
						catch (Exception)
						{
							throw;
						}
					}

					// prepare email
					var email = requestBody.Get<string>("Email");
					if (!string.IsNullOrWhiteSpace(email))
						try
						{
							email = CryptoService.RSADecrypt(Base.AspNet.Global.RSA, email);
							request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>())
							{
								{ "Email", email.Encrypt() }
							};
						}
						catch (Exception ex)
						{
							throw new InvalidDataException("Request JSON is invalid (email must be encrypted by RSA before sending)", ex);
						}

					// prepare password
					var password = requestBody.Get<string>("Password");
					if (!string.IsNullOrWhiteSpace(password))
						try
						{
							password = CryptoService.RSADecrypt(Base.AspNet.Global.RSA, password);
							request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>())
							{
								{ "Password", password.Encrypt() }
							};
						}
						catch (Exception ex)
						{
							throw new InvalidDataException("Request JSON is invalid (password must be encrypted by RSA before sending)", ex);
						}

					// prepare old-password
					var oldPassword = requestBody.Get<string>("OldPassword");
					if (!string.IsNullOrWhiteSpace(oldPassword))
						try
						{
							oldPassword = CryptoService.RSADecrypt(Base.AspNet.Global.RSA, oldPassword);
							request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>())
							{
								{ "OldPassword", oldPassword.Encrypt() }
							};
						}
						catch (Exception ex)
						{
							throw new InvalidDataException("Request JSON is invalid (password must be encrypted by RSA before sending)", ex);
						}

					// preapare
					var objectIdentity = request.GetObjectIdentity();

					// prepare to register/create new account
					if (string.IsNullOrWhiteSpace(objectIdentity))
					{
						if (request.Session.SessionID.Encrypt(Base.AspNet.Global.AESKey.Reverse(), true).Equals(request.GetHeaderParameter("x-create")))
							request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>())
							{
								{ "x-create", "" }
							};
					}

					// prepare to invite
					else if ("invite".IsEquals(objectIdentity))
						request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>())
						{
							{ "x-invite", "" }
						};

					// prepare to reset password
					else if ("reset".IsEquals(objectIdentity) && (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(captcha)))
						throw new InvalidSessionException("Request JSON is invalid (email/captcha is null or empty)");

					// prepare to update password
					else if ("password".IsEquals(objectIdentity) && (string.IsNullOrWhiteSpace(oldPassword) || string.IsNullOrWhiteSpace(password)))
						throw new InvalidSessionException("Request JSON is invalid (password is null or empty)");

					// prepare to update email
					else if ("email".IsEquals(objectIdentity) && (string.IsNullOrWhiteSpace(oldPassword) || string.IsNullOrWhiteSpace(email)))
						throw new InvalidSessionException("Request JSON is invalid (password/email is null or empty)");
				}
				catch (Exception ex)
				{
#if DEBUG || PROCESSLOGS
					await Base.AspNet.Global.WriteLogsAsync(request.CorrelationID, "Internal", "Error occurred while processing account", ex).ConfigureAwait(false);
#endif
					await Base.AspNet.Global.WriteLogsAsync(request.CorrelationID, "Security.Errors", "Error occurred while processing account", ex).ConfigureAwait(false);
					context.ShowError(ex, request);
					return;
				}
			#endregion

			// process the request of session
			if (isSessionProccessed)
				switch (request.Verb)
				{
					case "GET":
						await InternalAPIs.RegisterSessionAsync(context, request, accessToken).ConfigureAwait(false);
						break;

					case "POST":
						await InternalAPIs.SignSessionInAsync(context, request).ConfigureAwait(false);
						break;

					case "PUT":
						await InternalAPIs.ValidateOTPSessionAsync(context, request).ConfigureAwait(false);
						break;

					case "DELETE":
						await InternalAPIs.SignSessionOutAsync(context, request).ConfigureAwait(false);
						break;

					default:
						context.ShowError(new MethodNotAllowedException(request.Verb), request, false);
						break;
				}

			// process the request of activation
			else if (isActivationProccessed)
			{
				// prepare device identity
				if (string.IsNullOrWhiteSpace(request.Session.DeviceID))
					request.Session.DeviceID = (request.Session.AppName + "/" + request.Session.AppPlatform + "@" + (request.Session.AppAgent ?? "N/A")).GetHMACSHA384(request.Session.SessionID, true) + "@pwa";

				// activate
				try
				{
					await InternalAPIs.ActivateAsync(context, request).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
#if DEBUG || PROCESSLOGS
					await Base.AspNet.Global.WriteLogsAsync(request.CorrelationID, "Internal", "Error occurred while activating", ex).ConfigureAwait(false);
#endif
					await Base.AspNet.Global.WriteLogsAsync(request.CorrelationID, "Security.Errors", "Error occurred while activating", ex).ConfigureAwait(false);
					context.ShowError(ex, request);
				}
			}

			// process the request of services
			else
				try
				{
					// process
					var response = await InternalAPIs.CallServiceAsync(request).ConfigureAwait(false);

					// special: request to update sessions of an account
					if (isAccountProccessed && request.Verb.IsEquals("PUT"))
						await InternalAPIs.RequestUpdateSessionsAsync(request).ConfigureAwait(false);

					// response
					await context.WriteResponseAsync(response).ConfigureAwait(false);

#if DEBUG || PROCESSLOGS
					await Base.AspNet.Global.WriteLogsAsync(request.CorrelationID, "Internal", $"Response:\r\n{response.ToString(Formatting.Indented)}").ConfigureAwait(false);
#endif
				}
				catch (Exception ex)
				{
#if DEBUG || PROCESSLOGS
					await Base.AspNet.Global.WriteLogsAsync(request.CorrelationID, "Internal", "Error occurred while processing", ex).ConfigureAwait(false);
#endif
					context.ShowError(ex, request);
				}
		}

		#region Register a session
		static async Task RegisterSessionAsync(HttpContext context, RequestInfo requestInfo, string accessToken)
		{
			// session of visitor/system account
			if (requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.IsSystemAccount)
				try
				{
					// prepare access token
					accessToken = string.IsNullOrWhiteSpace(accessToken)
						? User.GetAccessToken(requestInfo.Session.User, Base.AspNet.Global.RSA, Base.AspNet.Global.AESKey)
						: accessToken;

					// generate session
					var session = InternalAPIs.GenerateSessionJson(requestInfo, accessToken);

					// initialize session
					if (context.Request.QueryString["register"] == null)
					{
						// generate device identity
						if (string.IsNullOrWhiteSpace(requestInfo.Session.DeviceID))
						{
							requestInfo.Session.DeviceID = (requestInfo.Session.AppName + "/" + requestInfo.Session.AppPlatform + "@" + (requestInfo.Session.AppAgent ?? "N/A")).GetHMACSHA384(requestInfo.Session.SessionID, true) + "@pwa";
							session["DeviceID"] = requestInfo.Session.DeviceID;
						}

						// update cache
						await Global.Cache.SetAsync("Session#" + requestInfo.Session.SessionID, session.ToString(Formatting.None), 2).ConfigureAwait(false);
					}

					// register session
					else
					{
						// validate
						if (!requestInfo.Session.SessionID.Equals(context.Request.QueryString["register"].Decrypt(Base.AspNet.Global.AESKey.Reverse(), true)))
							throw new InvalidRequestException();

						// register with user service
						await Task.WhenAll(
							InternalAPIs.CallServiceAsync(requestInfo.Session, "Users", "Session", "POST", session.ToString(Formatting.None)),
							Global.Cache.SetAsync("Session#" + requestInfo.Session.SessionID, session.ToString(Formatting.None), 180)
						).ConfigureAwait(false);
					}

					// response
					var json = new JObject()
					{
						{ "ID", requestInfo.Session.SessionID },
						{ "DeviceID", requestInfo.Session.DeviceID }
					};
					requestInfo.Session.UpdateSessionJson(json, accessToken);
					await context.WriteResponseAsync(json).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
#if DEBUG || PROCESSLOGS
					await Base.AspNet.Global.WriteLogsAsync(requestInfo.CorrelationID, "Internal", "Error occurred while registering session", ex).ConfigureAwait(false);
#endif
					await Base.AspNet.Global.WriteLogsAsync(requestInfo.CorrelationID, "Security.Errors", "Error occurred while registering session", ex).ConfigureAwait(false);
					context.ShowError(ex, requestInfo);
				}

			// session of authenticated account
			else
				try
				{
					// call service to get session
					var session = await InternalAPIs.CallServiceAsync(requestInfo.Session, "Users", "Session").ConfigureAwait(false);
					var jsonUserID = session?["UserID"];
					var jsonAccessToken = session?["AccessToken"];

					// verify access token
					if (jsonUserID == null || !(jsonUserID is JValue) || (jsonUserID as JValue).Value == null || !requestInfo.Session.User.ID.Equals((jsonUserID as JValue).Value as string))
						throw new InvalidTokenException();
					else if (jsonAccessToken == null || !(jsonAccessToken is JValue) || (jsonAccessToken as JValue).Value == null || !accessToken.Equals(((jsonAccessToken as JValue).Value as string).Decrypt()))
						throw new TokenRevokedException();

					// update session
					session["RenewedAt"] = DateTime.Now;
					session["ExpiredAt"] = DateTime.Now.AddDays(60);
					session["AccessToken"] = ((jsonAccessToken as JValue).Value as string).Decrypt();
					session["IP"] = requestInfo.Session.IP;
					session["DeviceID"] = requestInfo.Session.DeviceID;
					session["AppInfo"] = requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform;
					session["Online"] = true;

					// register with user service
					await Task.WhenAll(
						InternalAPIs.CallServiceAsync(requestInfo.Session, "Users", "Session", "POST", session.ToString(Formatting.None)),
						Global.Cache.SetAsync("Session#" + requestInfo.Session.SessionID, session.ToString(Formatting.None), 180)
					).ConfigureAwait(false);

					// response
					var json = new JObject()
					{
						{ "ID", requestInfo.Session.SessionID },
						{ "DeviceID", requestInfo.Session.DeviceID }
					};
					requestInfo.Session.UpdateSessionJson(json, accessToken);
					await context.WriteResponseAsync(json).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
#if DEBUG || PROCESSLOGS
					await Base.AspNet.Global.WriteLogsAsync(requestInfo.CorrelationID, "Internal", "Error occurred while registering session", ex).ConfigureAwait(false);
#endif
					await Base.AspNet.Global.WriteLogsAsync(requestInfo.CorrelationID, "Security.Errors", "Error occurred while registering session", ex).ConfigureAwait(false);
					context.ShowError(ex, requestInfo);
				}
		}
		#endregion

		#region Sign a session in
		static async Task SignSessionInAsync(HttpContext context, RequestInfo requestInfo)
		{
			try
			{
				// validate
				var body = requestInfo.GetBodyExpando();
				if (body == null)
					throw new InvalidSessionException("Sign-in JSON is invalid (empty)");

				var email = body.Get<string>("Email");
				var password = body.Get<string>("Password");

				if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
					throw new InvalidSessionException("Sign-in JSON is invalid (email/password is null or empty)");

				try
				{
					email = CryptoService.RSADecrypt(Base.AspNet.Global.RSA, email);
					password = CryptoService.RSADecrypt(Base.AspNet.Global.RSA, password);
				}
				catch (Exception ex)
				{
					throw new InvalidDataException("Sign-in JSON is invalid (account/password must be encrypted by RSA before sending)", ex);
				}

				// call service to perform sign in
				var json = await InternalAPIs.CallServiceAsync(new RequestInfo(requestInfo.Session)
				{
					ServiceName = "Users",
					ObjectName = "Session",
					Verb = "PUT",
					Body = new JObject()
					{
						{ "Email", email.Encrypt() },
						{ "Password", password.Encrypt() }
					}.ToString(Formatting.None),
					CorrelationID = requestInfo.CorrelationID
				}).ConfigureAwait(false);

				// two-factors authentication
				var require2FA = json["Require2FA"] != null
					? (json["Require2FA"] as JValue).Value.CastAs<bool>()
					: false;

				if (require2FA)
					json = new JObject()
					{
						{ "ID", (json["ID"] as JValue).Value as string },
						{ "Require2FA", true },
						{ "Providers", json["Providers"] as JArray }
					};

				else
				{
					// register new session
					await Global.Cache.RemoveAsync("Session#" + requestInfo.Session.SessionID).ConfigureAwait(false);

					requestInfo.Session.User = json.FromJson<User>();
					requestInfo.Session.SessionID = UtilityService.NewUID;
					var accessToken = User.GetAccessToken(requestInfo.Session.User, Base.AspNet.Global.RSA, Base.AspNet.Global.AESKey);
					await InternalAPIs.CreateSessionAsync(requestInfo, accessToken).ConfigureAwait(false);

					// response
					json = new JObject()
					{
						{ "ID", requestInfo.Session.SessionID },
						{ "DeviceID", requestInfo.Session.DeviceID }
					};
					requestInfo.Session.UpdateSessionJson(json, accessToken);
				}

				// response
				await Task.WhenAll(
					context.WriteResponseAsync(json),
					Global.Cache.RemoveAsync("Attempt#" + requestInfo.Session.IP)
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				// wait
				var attempt = await Global.Cache.ExistsAsync("Attempt#" + requestInfo.Session.IP).ConfigureAwait(false)
					? await Global.Cache.GetAsync<int>("Attempt#" + requestInfo.Session.IP).ConfigureAwait(false)
					: 0;
				attempt++;

				await Task.WhenAll(
					Task.Delay(567 + ((attempt - 1) * 5678)),
					Global.Cache.SetAsync("Attempt#" + requestInfo.Session.IP, attempt)
				).ConfigureAwait(false);

				// show error
#if DEBUG || PROCESSLOGS
				await Base.AspNet.Global.WriteLogsAsync(requestInfo.CorrelationID, "Internal", "Error occurred while signing-in session", ex).ConfigureAwait(false);
#endif
				await Base.AspNet.Global.WriteLogsAsync(requestInfo.CorrelationID, "Security.Errors", "Error occurred while signing-in session", ex).ConfigureAwait(false);
				context.ShowError(ex, requestInfo);
			}
		}
		#endregion

		#region Validate an OTP session
		static async Task ValidateOTPSessionAsync(HttpContext context, RequestInfo requestInfo)
		{
			try
			{
				// validate
				var body = requestInfo.GetBodyExpando();
				if (body == null)
					throw new InvalidSessionException("OTP is invalid (empty)");

				var id = body.Get<string>("ID");
				var otp = body.Get<string>("OTP");
				var info = body.Get<string>("Info");

				if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(otp) || string.IsNullOrWhiteSpace(info))
					throw new InvalidSessionException("OTP is invalid (empty)");

				// call service to perform sign in
				var json = await InternalAPIs.CallServiceAsync(new RequestInfo(requestInfo.Session)
				{
					ServiceName = "Users",
					ObjectName = "OTP",
					Verb = "POST",
					Body = new JObject()
					{
						{ "ID", id },
						{ "OTP", otp },
						{ "Info", info }
					}.ToString(Formatting.None),
					CorrelationID = requestInfo.CorrelationID
				}).ConfigureAwait(false);

				// register new session
				await Global.Cache.RemoveAsync("Session#" + requestInfo.Session.SessionID).ConfigureAwait(false);

				requestInfo.Session.User = json.FromJson<User>();
				requestInfo.Session.SessionID = UtilityService.NewUID;
				var accessToken = User.GetAccessToken(requestInfo.Session.User, Base.AspNet.Global.RSA, Base.AspNet.Global.AESKey);
				await InternalAPIs.CreateSessionAsync(requestInfo, accessToken).ConfigureAwait(false);

				// response
				json = new JObject()
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "DeviceID", requestInfo.Session.DeviceID }
				};
				requestInfo.Session.UpdateSessionJson(json, accessToken);

				// response
				await Task.WhenAll(
					context.WriteResponseAsync(json),
					Global.Cache.RemoveAsync("Attempt#" + requestInfo.Session.IP)
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				// wait
				var attempt = await Global.Cache.ExistsAsync("Attempt#" + requestInfo.Session.IP).ConfigureAwait(false)
					? await Global.Cache.GetAsync<int>("Attempt#" + requestInfo.Session.IP).ConfigureAwait(false)
					: 0;
				attempt++;

				await Task.WhenAll(
					Task.Delay(567 + ((attempt - 1) * 5678)),
					Global.Cache.SetAsync("Attempt#" + requestInfo.Session.IP, attempt)
				).ConfigureAwait(false);

				// show error
#if DEBUG || PROCESSLOGS
				await Base.AspNet.Global.WriteLogsAsync(requestInfo.CorrelationID, "Internal", "Error occurred while signing-in session", ex).ConfigureAwait(false);
#endif
				await Base.AspNet.Global.WriteLogsAsync(requestInfo.CorrelationID, "Security.Errors", "Error occurred while signing-in session", ex).ConfigureAwait(false);
				context.ShowError(ex, requestInfo);
			}
		}
		#endregion

		#region Sign a session out
		static async Task SignSessionOutAsync(HttpContext context, RequestInfo requestInfo)
		{
			try
			{
				// check
				if (requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.IsSystemAccount)
					throw new InvalidRequestException();

				// call service to perform sign out
				await InternalAPIs.CallServiceAsync(requestInfo.Session, "Users", "Session", "DELETE").ConfigureAwait(false);

				await Task.WhenAll(
					Global.Cache.RemoveAsync("Session#" + requestInfo.Session.SessionID),
					requestInfo.Session.SendOnlineStatusAsync(false)
				).ConfigureAwait(false);

				// create a new session
				requestInfo.Session.SessionID = UtilityService.NewUID;
				requestInfo.Session.User = new User();

				// register the new session of visitor
				var accessToken = User.GetAccessToken(requestInfo.Session.User, Base.AspNet.Global.RSA, Base.AspNet.Global.AESKey);
				var session = InternalAPIs.GenerateSessionJson(requestInfo, accessToken);
				await Global.Cache.SetAsync("Session#" + requestInfo.Session.SessionID, session.ToString(Formatting.None), 180).ConfigureAwait(false);

				// response
				var json = new JObject()
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "DeviceID", requestInfo.Session.DeviceID }
				};
				requestInfo.Session.UpdateSessionJson(json, accessToken);
				await context.WriteResponseAsync(json).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
#if DEBUG || PROCESSLOGS
				await Base.AspNet.Global.WriteLogsAsync(requestInfo.CorrelationID, "Internal", "Error occurred while signing-out session", ex).ConfigureAwait(false);
#endif
				await Base.AspNet.Global.WriteLogsAsync(requestInfo.CorrelationID, "Security.Errors", "Error occurred while signing-out session", ex).ConfigureAwait(false);
				context.ShowError(ex, requestInfo);
			}
		}
		#endregion

		#region Activation
		static async Task ActivateAsync(HttpContext context, RequestInfo requestInfo)
		{
			// call service to activate
			var json = await InternalAPIs.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Activate", "GET", requestInfo.Query, requestInfo.Header, "", requestInfo.Extra, requestInfo.CorrelationID)).ConfigureAwait(false);

			// update user information & get access token
			requestInfo.Session.User = json.FromJson<User>();
			var accessToken = User.GetAccessToken(requestInfo.Session.User, Base.AspNet.Global.RSA, Base.AspNet.Global.AESKey);

			// register the session
			var session = InternalAPIs.GenerateSessionJson(requestInfo, accessToken).ToString(Formatting.None);
			await Task.WhenAll(
				InternalAPIs.CallServiceAsync(requestInfo.Session, "Users", "Session", "POST", session),
				requestInfo.Session.SendOnlineStatusAsync(true),
				Global.Cache.SetAsync("Session#" + requestInfo.Session.SessionID, session, 180)
			).ConfigureAwait(false);

			// response
			json = new JObject()
			{
				{ "ID", requestInfo.Session.SessionID },
				{ "DeviceID", requestInfo.Session.DeviceID }
			};
			requestInfo.Session.UpdateSessionJson(json, accessToken);
			await context.WriteResponseAsync(json).ConfigureAwait(false);
		}
		#endregion

		#region Create a session
		static JObject GenerateSessionJson(RequestInfo requestInfo, string accessToken = null, bool isOnline = true)
		{
			return new JObject()
			{
				{ "ID", requestInfo.Session.SessionID },
				{ "IssuedAt", DateTime.Now },
				{ "RenewedAt", DateTime.Now },
				{ "ExpiredAt", DateTime.Now.AddDays(60) },
				{ "UserID", requestInfo.Session.User.ID },
				{ "AccessToken", accessToken ?? User.GetAccessToken(requestInfo.Session.User, Base.AspNet.Global.RSA, Base.AspNet.Global.AESKey) },
				{ "IP", requestInfo.Session.IP },
				{ "DeviceID", requestInfo.Session.DeviceID },
				{ "AppInfo", requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform },
				{ "Online", isOnline }
			};
		}

		static async Task CreateSessionAsync(RequestInfo requestInfo, string accessToken = null)
		{
			var session = InternalAPIs.GenerateSessionJson(requestInfo, accessToken);
			await InternalAPIs.CallServiceAsync(new RequestInfo(requestInfo.Session)
			{
				ServiceName = "Users",
				ObjectName = "Session",
				Verb = "POST",
				Body = session.ToString(Formatting.None),
				CorrelationID = requestInfo.CorrelationID
			}).ConfigureAwait(false);

			await Task.WhenAll(
				Global.Cache.SetAsync("Session#" + requestInfo.Session.SessionID, session.ToString(Formatting.None), 180),
				requestInfo.Session.SendOnlineStatusAsync(true)
			).ConfigureAwait(false);
		}
		#endregion

		#region Verify a session
		internal static async Task<bool> CheckSessionExistAsync(Session session)
		{
			// pre-check
			if (session == null || string.IsNullOrWhiteSpace(session.SessionID))
				return false;
			else if (await Global.Cache.ExistsAsync("Session#" + session.SessionID).ConfigureAwait(false))
				return true;

			// check with user service
			var result = await InternalAPIs.CallServiceAsync(session, "Users", "Session", "GET", null, new Dictionary<string, string>()
			{
				{ "Exist", "" }
			}).ConfigureAwait(false);
			var isExisted = result?["Existed"];
			return isExisted != null && isExisted is JValue && (isExisted as JValue).Value != null && (isExisted as JValue).Value.CastAs<bool>() == true;
		}

		internal static async Task VerifySessionIntegrityAsync(Session session, string accessToken)
		{
			// pre-check
			if (session == null || string.IsNullOrWhiteSpace(session.SessionID))
				throw new SessionNotFoundException();
			else if (string.IsNullOrWhiteSpace(accessToken))
				throw new TokenNotFoundException();

			// check with cached
			var cached = await Global.Cache.GetAsync<string>("Session#" + session.SessionID).ConfigureAwait(false);
			if (!string.IsNullOrWhiteSpace(cached))
			{
				var info = cached.ToExpandoObject();
				if (info.Get<DateTime>("ExpiredAt") < DateTime.Now)
					throw new SessionExpiredException();
				else if (!accessToken.Equals(info.Get<string>("AccessToken")))
					throw new TokenRevokedException();
			}

			// check with user service
			else
				await InternalAPIs.CallServiceAsync(session, "Users", "Session", "GET", null, new Dictionary<string, string>()
				{
					{ "Verify", "" },
					{ "AccessToken", accessToken.Encrypt() }
				}).ConfigureAwait(false);
		}
		#endregion

		#region Update sessions (revoke)
		internal static async Task RequestUpdateSessionsAsync(RequestInfo requestInfo)
		{
			// check
			var userID = requestInfo.GetObjectIdentity();
			if (string.IsNullOrWhiteSpace(userID) || !userID.IsValidUUID())
				return;

			// get user information
			var user = (await InternalAPIs.CallServiceAsync(new RequestInfo(requestInfo.Session)
			{
				ServiceName = "Users",
				ObjectName = "Account",
				Verb = "GET",
				Query = requestInfo.Query,
				CorrelationID = requestInfo.CorrelationID
			}).ConfigureAwait(false)).FromJson<User>();

			// send inter-communicate message to tell services update old sessions with new access token
			await Global.SendInterCommunicateMessageAsync(new CommunicateMessage()
			{
				ServiceName = "Users",
				Type = "Session",
				Data = new JObject()
				{
					{ "UserID", user.ID },
					{ "AccessToken", User.GetAccessToken(user, Base.AspNet.Global.RSA, Base.AspNet.Global.AESKey).Encrypt() }
				}
			}).ConfigureAwait(false);
		}
		#endregion

		#region Helper: call service
		internal static Task<JObject> CallServiceAsync(RequestInfo requestInfo, string objectLogName = "Internal")
		{
			return Base.AspNet.Global.CallServiceAsync(requestInfo, Base.AspNet.Global.CancellationTokenSource.Token,
				(info) =>
				{
#if DEBUG || PROCESSLOGS
					Base.AspNet.Global.WriteLogs(info.CorrelationID, objectLogName, $"Call the service [net.vieapps.services.{info.ServiceName}]\r\n{info.ToJson().ToString(Formatting.Indented)}");
#endif
				},
				(info, json) =>
				{
#if DEBUG || PROCESSLOGS
					Base.AspNet.Global.WriteLogs(info.CorrelationID, objectLogName, $"Results from the service [net.vieapps.services.{info.ServiceName}]\r\n{json.ToString(Formatting.Indented)}");
#endif
				},
				(info, ex) =>
				{
#if DEBUG || PROCESSLOGS
					Base.AspNet.Global.WriteLogs(info.CorrelationID, objectLogName, $"Error occurred while calling the service [net.vieapps.services.{info.ServiceName}]", ex);
#endif
				}
			);
		}

		internal static Task<JObject> CallServiceAsync(Session session, string serviceName, string objectName, string verb = "GET", string body = null, Dictionary<string, string> extra = null, string correlationID = null)
		{
			return InternalAPIs.CallServiceAsync(new RequestInfo(session, serviceName, objectName, verb)
			{
				Body = body ?? "",
				Extra = extra ?? new Dictionary<string, string>(),
				CorrelationID = correlationID ?? Base.AspNet.Global.GetCorrelationID()
			});
		}
		#endregion

		#region Helper: working with response JSON, online status, ...
		internal static void UpdateSessionJson(this Session session, JObject json, string accessToken)
		{
			json["ID"] = session.SessionID.Encrypt(Base.AspNet.Global.AESKey.Reverse(), true);
			json.Add(new JProperty("Keys", new JObject()
			{
				{
					"RSA",
					new JObject()
					{
						{ "Exponent", Base.AspNet.Global.RSAExponent },
						{ "Modulus", Base.AspNet.Global.RSAModulus }
					}
				},
				{
					"AES",
					new JObject()
					{
						{ "Key", Base.AspNet.Global.GenerateEncryptionKey(session.SessionID).ToHexa() },
						{ "IV", Base.AspNet.Global.GenerateEncryptionIV(session.SessionID).ToHexa() }
					}
				},
				{
					"JWT",
					Base.AspNet.Global.GenerateJWTKey()
				}
			}));
			json.Add(new JProperty("JWT", session.GetJSONWebToken(accessToken)));
		}

		internal static Task SendOnlineStatusAsync(this Session session, bool isOnline)
		{
			return session.User == null || session.User.ID.Equals("")
				? Task.CompletedTask
				: Global.SendInterCommunicateMessageAsync(new CommunicateMessage()
				{
					ServiceName = "Users",
					Type = "OnlineStatus",
					Data = new JObject()
					{
						{ "UserID", session.User.ID },
						{ "SessionID", session.SessionID },
						{ "DeviceID", session.DeviceID },
						{ "AppName", session.AppName },
						{ "AppPlatform", session.AppPlatform },
						{ "IP", session.IP },
						{ "IsOnline", isOnline },
					}
				});
		}

		static async Task WriteResponseAsync(this HttpContext context, JObject json)
		{
			context.Response.ContentType = "application/json";
			await context.Response.Output.WriteAsync((new JObject()
			{
				{ "Status", "OK" },
				{ "Data", json }
			}).ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None)).ConfigureAwait(false);
		}
		#endregion

	}
}