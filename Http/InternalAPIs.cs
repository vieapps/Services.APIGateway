#region Related components
using System;
using System.IO;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Reactive.Subjects;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using WampSharp.V2;
using WampSharp.V2.Core.Contracts;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Caching;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class InternalAPIs
	{

		#region Properties
		internal static Cache Cache { get; set; }
		internal static ILogger Logger { get; set; }
		internal static List<string> ExcludedHeaders { get; } = "connection,accept,accept-encoding,accept-language,cache-control,cookie,content-type,content-length,user-agent,referer,host,origin,if-modified-since,if-none-match,upgrade-insecure-requests,ms-aspnetcore-token,x-original-proto,x-original-for".ToList();
		internal static HashSet<string> NoTokenRequiredServices { get; } = (UtilityService.GetAppSetting("NoTokenRequiredServices", "") + "|indexes").ToLower().ToHashSet('|', true);
		#endregion

		internal static async Task ProcessRequestAsync(HttpContext context)
		{

			#region prepare the requesting information			
			var queryString = context.Request.QueryString.ToDictionary(query =>
			{
				var pathSegments = context.GetRequestPathSegments();
				query["service-name"] = !string.IsNullOrWhiteSpace(pathSegments[0]) ? pathSegments[0].GetANSIUri() : "";
				query["object-name"] = pathSegments.Length > 1 && !string.IsNullOrWhiteSpace(pathSegments[1]) ? pathSegments[1].GetANSIUri() : "";
				query["object-identity"] = pathSegments.Length > 2 && !string.IsNullOrWhiteSpace(pathSegments[2]) ? pathSegments[2].GetANSIUri() : "";
			});

			var requestInfo = new RequestInfo
			{
				Session = context.GetSession(),
				Verb = context.Request.Method,
				ServiceName = queryString["service-name"],
				ObjectName = queryString["object-name"],
				Query = queryString,
				Header = context.Request.Headers.ToDictionary(dictionary => InternalAPIs.ExcludedHeaders.ForEach(name => dictionary.Remove(name))),
				CorrelationID = context.GetCorrelationID()
			};

			bool isSessionProccessed = false, isSessionInitialized = false, isAccountProccessed = false, isActivationProccessed = false;

			if (requestInfo.ServiceName.IsEquals("users"))
			{
				if ("session".IsEquals(requestInfo.ObjectName))
				{
					isSessionProccessed = true;
					isSessionInitialized = requestInfo.Verb.IsEquals("GET");
				}
				else if ("account".IsEquals(requestInfo.ObjectName))
					isAccountProccessed = requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT");
				else if ("activate".IsEquals(requestInfo.ObjectName))
					isActivationProccessed = requestInfo.Verb.IsEquals("GET");
			}
			#endregion

			#region prepare token
			try
			{
				// get token
				var token = requestInfo.GetParameter("x-app-token");

				// support for Bearer token
				if (string.IsNullOrWhiteSpace(token))
				{
					token = context.GetHeaderParameter("authorization");
					token = token != null && token.IsStartsWith("Bearer") ? token.ToArray(" ").Last() : null;
				}

				// re-assign
				if (!requestInfo.Header.ContainsKey("x-app-token"))
					requestInfo.Header["x-app-token"] = token;

				// parse and update information from token
				var tokenIsRequired = isActivationProccessed
					? false
					: isSessionInitialized && (requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.IsSystemAccount) && !requestInfo.Query.ContainsKey("register")
						? false
						: !InternalAPIs.NoTokenRequiredServices.Contains(requestInfo.ServiceName);

				if (!string.IsNullOrWhiteSpace(token))
					await context.UpdateWithAuthenticateTokenAsync(requestInfo.Session, token).ConfigureAwait(false);
				else if (tokenIsRequired)
					throw new InvalidSessionException("Session is invalid (Token is not found)");

				// check existed of session
				if (tokenIsRequired && !await context.CheckSessionExistAsync(requestInfo.Session).ConfigureAwait(false))
					throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
			}
			catch (Exception ex)
			{
				context.WriteError(InternalAPIs.Logger, ex, requestInfo, null, false);
				if (Global.IsDebugLogEnabled)
					Global.Logger.LogError(ex.Message, ex);
				return;
			}
			#endregion

			#region prepare others (session identity, request body)
			// new session
			if (string.IsNullOrWhiteSpace(requestInfo.Session.SessionID))
				requestInfo.Session.SessionID = requestInfo.Session.User.SessionID = UtilityService.NewUUID;

			// request body
			if (requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT"))
				try
				{
					requestInfo.Body = await context.ReadTextAsync(Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					await context.WriteLogsAsync(InternalAPIs.Logger, "InternalAPIs", "Error occurred while parsing body of the request", ex).ConfigureAwait(false);
				}

			else if (requestInfo.Verb.IsEquals("GET") && requestInfo.Query.ContainsKey("x-body"))
				try
				{
					requestInfo.Body = requestInfo.Query["x-body"].Url64Decode();
				}
				catch (Exception ex)
				{
					await context.WriteLogsAsync(InternalAPIs.Logger, "InternalAPIs", "Error occurred while parsing body of the 'x-body' parameter", ex).ConfigureAwait(false);
				}
			#endregion

			#region [extra] verify captcha
			// verfy captcha
			var captchaIsValid = false;
			if (requestInfo.Header.ContainsKey("x-captcha"))
				try
				{
					requestInfo.Header.TryGetValue("x-captcha-registered", out string registered);
					requestInfo.Header.TryGetValue("x-captcha-input", out string input);
					if (string.IsNullOrWhiteSpace(registered) || string.IsNullOrWhiteSpace(input))
						throw new InvalidSessionException("Captcha code is invalid");

					try
					{
						var key = context.GetEncryptionKey(requestInfo.Session);
						var iv = context.GetEncryptionIV(requestInfo.Session);
						registered = registered.Decrypt(key, iv);
						input = input.Decrypt(key, iv);
					}
					catch (Exception ex)
					{
						throw new InvalidSessionException("Captcha code is invalid", ex);
					}

					captchaIsValid = CaptchaService.IsCodeValid(registered, input)
						? true
						: throw new InformationInvalidException("Captcha code is invalid");
				}
				catch (Exception ex)
				{
					context.WriteError(InternalAPIs.Logger, ex, requestInfo, null, false);
					if (Global.IsDebugLogEnabled)
						Global.Logger.LogError(ex.Message, ex);
					return;
				}
			#endregion

			#region [extra] prepare information of an account
			if (isAccountProccessed)
				try
				{
					var requestBody = requestInfo.GetBodyExpando();
					if (requestBody == null)
						throw new InvalidSessionException("Request JSON is invalid (empty)");

					// prepare email
					var email = requestBody.Get<string>("Email");
					if (!string.IsNullOrWhiteSpace(email))
						try
						{
							email = Global.RSA.Decrypt(email);
							requestInfo.Extra["Email"] = email.Encrypt(Global.EncryptionKey);
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
							password = Global.RSA.Decrypt(password);
							requestInfo.Extra["Password"] = password.Encrypt(Global.EncryptionKey);
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
							oldPassword = Global.RSA.Decrypt(oldPassword);
							requestInfo.Extra["OldPassword"] = oldPassword.Encrypt(Global.EncryptionKey);
						}
						catch (Exception ex)
						{
							throw new InvalidDataException("Request JSON is invalid (password must be encrypted by RSA before sending)", ex);
						}

					// prepare roles
					var roles = requestBody.Get<string>("Roles");
					if (!string.IsNullOrWhiteSpace(roles))
						try
						{
							requestInfo.Extra["Roles"] = Global.RSA.Decrypt(roles).Encrypt(Global.EncryptionKey);
						}
						catch (Exception ex)
						{
							await context.WriteLogsAsync(InternalAPIs.Logger, "InternalAPIs", $"Error occurred while parsing roles: {ex.Message}", ex);
						}

					// prepare privileges
					var privileges = requestBody.Get<string>("Privileges");
					if (!string.IsNullOrWhiteSpace(privileges))
						try
						{
							requestInfo.Extra["Privileges"] = Global.RSA.Decrypt(privileges).Encrypt(Global.EncryptionKey);
						}
						catch (Exception ex)
						{
							await context.WriteLogsAsync(InternalAPIs.Logger, "InternalAPIs", $"Error occurred while parsing privileges: {ex.Message}", ex);
						}

					// prepare information of related service
					var relatedInfo = requestInfo.Query.ContainsKey("related-service")
						? requestBody.Get<string>("RelatedInfo")
						: null;
					if (!string.IsNullOrWhiteSpace(relatedInfo))
						try
						{
							relatedInfo = Global.RSA.Decrypt(relatedInfo);
							requestInfo.Extra["RelatedInfo"] = relatedInfo.Encrypt(Global.EncryptionKey);
						}
						catch (Exception ex)
						{
							await context.WriteLogsAsync(InternalAPIs.Logger, "InternalAPIs", $"Error occurred while parsing information of related service: {ex.Message}", ex);
						}

					// preapare
					var objectIdentity = requestInfo.GetObjectIdentity();

					// prepare to register/create new account
					if (string.IsNullOrWhiteSpace(objectIdentity))
					{
						if (!captchaIsValid)
							throw new InvalidSessionException("Captcha code is invalid");

						var requestCreateAccount = requestInfo.GetHeaderParameter("x-create");
						if (!string.IsNullOrWhiteSpace(requestCreateAccount) && requestCreateAccount.Equals(requestInfo.Session.SessionID.GetEncryptedID()))
							requestInfo.Extra["x-create"] = "";
					}

					// prepare to invite
					else if ("invite".IsEquals(objectIdentity))
						requestInfo.Extra["x-invite"] = "";

					// prepare to reset password
					else if ("reset".IsEquals(objectIdentity) && (string.IsNullOrWhiteSpace(email) || !captchaIsValid))
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
					context.WriteError(InternalAPIs.Logger, ex, requestInfo, null, false);
					if (Global.IsDebugLogEnabled)
						Global.Logger.LogError(ex.Message, ex);
					return;
				}
			#endregion

			// set user principal
			context.User = new UserPrincipal(requestInfo.Session.User);

			// process request of sessions
			if (isSessionProccessed)
				switch (requestInfo.Verb)
				{
					case "GET":
						await context.RegisterSessionAsync(requestInfo).ConfigureAwait(false);
						break;

					case "POST":
						await context.SignSessionInAsync(requestInfo).ConfigureAwait(false);
						break;

					case "PUT":
						await context.ValidateOTPSessionAsync(requestInfo).ConfigureAwait(false);
						break;

					case "DELETE":
						await context.SignSessionOutAsync(requestInfo).ConfigureAwait(false);
						break;

					default:
						context.WriteError(new MethodNotAllowedException(requestInfo.Verb), requestInfo, null, false);
						break;
				}

			// process request of activations
			else if (isActivationProccessed)
			{
				// prepare device identity
				if (string.IsNullOrWhiteSpace(requestInfo.Session.DeviceID))
					requestInfo.Session.DeviceID = (requestInfo.Session.AppName + "/" + requestInfo.Session.AppPlatform + "@" + (requestInfo.Session.AppAgent ?? "N/A")).GetHMACSHA384(requestInfo.Session.SessionID, true) + "@pwa";

				// activate
				try
				{
					await context.ActivateAsync(requestInfo).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(ex, requestInfo);
				}
			}

			// process request of services
			else
				try
				{
					var response = await context.CallServiceAsync(requestInfo, Global.CancellationTokenSource.Token).ConfigureAwait(false);
					await context.WriteAsync(response, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None, requestInfo.CorrelationID, Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(InternalAPIs.Logger, ex, requestInfo);
				}
		}

		#region Check existing of a session
		internal static async Task<bool> CheckSessionExistAsync(this HttpContext context, Session session)
		{
			if (string.IsNullOrWhiteSpace(session?.SessionID))
				return false;

			else if (await context.IsSessionExistAsync(session).ConfigureAwait(false))
				return true;

			else
				return await InternalAPIs.Cache.ExistsAsync($"Session#{session.SessionID}").ConfigureAwait(false);
		}
		#endregion

		#region Register a session
		static async Task RegisterSessionAsync(this HttpContext context, RequestInfo requestInfo)
		{
			// session of visitor/system account
			if (requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.IsSystemAccount)
				try
				{
					// initialize session
					if (!requestInfo.Query.ContainsKey("register"))
					{
						// generate device identity
						if (string.IsNullOrWhiteSpace(requestInfo.Session.DeviceID))
							requestInfo.Session.DeviceID = (requestInfo.Session.AppName + "/" + requestInfo.Session.AppPlatform + "@" + (requestInfo.Session.AppAgent ?? "N/A")).GetHMACBLAKE128(requestInfo.Session.SessionID, true) + "@pwa";

						// store identity into cache for further use
						await InternalAPIs.Cache.SetAsync($"Session#{requestInfo.Session.SessionID}", requestInfo.Session.SessionID.Encrypt(Global.EncryptionKey), 7).ConfigureAwait(false);
					}

					// register session
					else
					{
						// validate
						var register = requestInfo.Query["register"].GetDecryptedID();
						if (!requestInfo.Session.SessionID.IsEquals(register) || !register.Encrypt(Global.EncryptionKey).IsEquals(await InternalAPIs.Cache.GetAsync<string>($"Session#{requestInfo.Session.SessionID}").ConfigureAwait(false)))
							throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");

						// register with user service
						await Task.WhenAll(
							context.CreateSessionAsync(requestInfo),
							InternalAPIs.Cache.RemoveAsync($"Session#{requestInfo.Session.SessionID}")
						).ConfigureAwait(false);
					}

					// response
					var json = new JObject
					{
						{ "ID", requestInfo.Session.SessionID },
						{ "DeviceID", requestInfo.Session.DeviceID }
					};
					context.UpdateSessionJson(requestInfo.Session, json);

					await Task.WhenAll(
						context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
						!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(InternalAPIs.Logger, "InternalAPIs", new List<string>
						{
							$"Successfully process request of session (registration of anonymous user)",
							$"Request: {requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
							$"Response: {json.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
							$"Execution times: {context.GetExecutionTimes()}"
						})
					).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(InternalAPIs.Logger, ex, requestInfo);
				}

			// session of authenticated account
			else
				try
				{
					// call service to get session
					var session = await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "GET", requestInfo.Query, requestInfo.Header)
					{
						Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
						{
							{ "Signature", requestInfo.Header["x-app-token"].GetHMACSHA256(Global.ValidationKey) }
						},
						CorrelationID = requestInfo.CorrelationID
					}, Global.CancellationTokenSource.Token, InternalAPIs.Logger).ConfigureAwait(false);

					// check
					if (session == null)
						throw new SessionNotFoundException();
					else if (!requestInfo.Session.User.ID.IsEquals(session.Get<string>("UserID")))
						throw new InvalidTokenException();

					// update session
					session["RenewedAt"] = DateTime.Now;
					session["ExpiredAt"] = DateTime.Now.AddDays(90);
					session["AccessToken"] = requestInfo.Session.User.GetAccessToken(Global.ECCKey);
					session["IP"] = requestInfo.Session.IP;
					session["DeviceID"] = requestInfo.Session.DeviceID;
					session["AppInfo"] = requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform;
					session["OSInfo"] = $"{requestInfo.Session.AppAgent.GetOSInfo()} [{requestInfo.Session.AppAgent}]";
					session["Online"] = true;

					// renew with user service
					var body = session.ToString(Formatting.None);
					await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "POST")
					{
						Body = body,
						Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
						{
							{ "Signature", body.GetHMACSHA256(Global.ValidationKey) }
						},
						CorrelationID = requestInfo.CorrelationID
					}, Global.CancellationTokenSource.Token, InternalAPIs.Logger).ConfigureAwait(false);

					// response
					var json = new JObject
					{
						{ "ID", requestInfo.Session.SessionID },
						{ "DeviceID", requestInfo.Session.DeviceID }
					};
					context.UpdateSessionJson(requestInfo.Session, json);

					await Task.WhenAll(
						context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
						!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(InternalAPIs.Logger, "InternalAPIs", new List<string>
						{
							$"Successfully process request of session (registration of authenticated user)",
							$"Request: {requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
							$"Response: {json.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
							$"Execution times: {context.GetExecutionTimes()}"
						})
					).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(InternalAPIs.Logger, ex, requestInfo);
				}
		}
		#endregion

		#region Create a session
		internal static JObject GenerateSessionJson(this RequestInfo requestInfo, bool is2FAVerified = false, bool isOnline = true)
			=> new JObject
			{
				{ "ID", requestInfo.Session.SessionID },
				{ "IssuedAt", DateTime.Now },
				{ "RenewedAt", DateTime.Now },
				{ "ExpiredAt", DateTime.Now.AddDays(90) },
				{ "UserID", requestInfo.Session.User.ID },
				{ "AccessToken", requestInfo.Session.User.GetAccessToken(Global.ECCKey) },
				{ "IP", requestInfo.Session.IP },
				{ "DeviceID", requestInfo.Session.DeviceID },
				{ "AppInfo", requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform },
				{ "OSInfo", $"{requestInfo.Session.AppAgent.GetOSInfo()} [{requestInfo.Session.AppAgent}]" },
				{ "Verification", is2FAVerified },
				{ "Online", isOnline }
			};

		static async Task CreateSessionAsync(this HttpContext context, RequestInfo requestInfo, bool is2FAVerified = false, bool isOnline = true)
		{
			var body = requestInfo.GenerateSessionJson(is2FAVerified, isOnline).ToString(Formatting.None);
			await Task.WhenAll(
				context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "POST")
				{
					Body = body,
					Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "Signature", body.GetHMACSHA256(Global.ValidationKey) }
					},
					CorrelationID = requestInfo.CorrelationID
				}, Global.CancellationTokenSource.Token, InternalAPIs.Logger),
				requestInfo.Session.SendOnlineStatusAsync(true)
			).ConfigureAwait(false);
		}
		#endregion

		#region Sign a session in
		static async Task SignSessionInAsync(this HttpContext context, RequestInfo requestInfo)
		{
			try
			{
				// check
				if (!await context.CheckSessionExistAsync(requestInfo.Session).ConfigureAwait(false))
					throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");

				// validate
				var request = requestInfo.GetBodyExpando();
				if (request == null)
					throw new InvalidTokenException("Sign-in JSON is invalid (empty)");

				var email = request.Get<string>("Email");
				var password = request.Get<string>("Password");

				if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
					throw new InvalidTokenException("Sign-in JSON is invalid (email/password is null or empty)");

				try
				{
					email = Global.RSA.Decrypt(email);
					password = Global.RSA.Decrypt(password);
				}
				catch (Exception ex)
				{
					throw new InvalidTokenException("Sign-in JSON is invalid (account/password must be encrypted by RSA before sending)", ex);
				}

				// call service to perform sign in
				var body = new JObject
				{
					{ "Type", request.Get("Type", "BuiltIn") },
					{ "Email", email.Encrypt(Global.EncryptionKey) },
					{ "Password", password.Encrypt(Global.EncryptionKey) },
				}.ToString(Formatting.None);

				var json = await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "PUT")
				{
					Body = body,
					Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "Signature", body.GetHMACSHA256(Global.ValidationKey) }
					},
					CorrelationID = requestInfo.CorrelationID
				}, Global.CancellationTokenSource.Token, InternalAPIs.Logger).ConfigureAwait(false);

				// two-factors authentication
				var oldSessionID = string.Empty;
				var require2FA = json["Require2FA"] != null
					? json.Get<bool>("Require2FA")
					: false;

				if (require2FA)
					json = new JObject
					{
						{ "ID", json.Get<string>("ID") },
						{ "Require2FA", true },
						{ "Providers", json["Providers"] as JArray }
					};

				else
				{
					// register new session
					oldSessionID = requestInfo.Session.SessionID;
					requestInfo.Session.User = json.FromJson<User>();
					requestInfo.Session.User.SessionID = requestInfo.Session.SessionID = UtilityService.NewUUID;
					await context.CreateSessionAsync(requestInfo).ConfigureAwait(false);

					// response
					json = new JObject
					{
						{ "ID", requestInfo.Session.SessionID },
						{ "DeviceID", requestInfo.Session.DeviceID }
					};
					context.UpdateSessionJson(requestInfo.Session, json);
				}

				// response
				await Task.WhenAll(
					context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
					InternalAPIs.Cache.RemoveAsync("Attempt#" + requestInfo.Session.IP),
					string.IsNullOrWhiteSpace(oldSessionID) ? Task.CompletedTask : InternalAPIs.Cache.RemoveAsync($"Session#{oldSessionID}"),
					!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(InternalAPIs.Logger, "InternalAPIs", new List<string>
					{
						$"Successfully process request of session (sign-in)",
						$"Request: {requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"Response: {json.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"Execution times: {context.GetExecutionTimes()}"
					})
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				// wait
				var attempt = await InternalAPIs.Cache.ExistsAsync("Attempt#" + requestInfo.Session.IP).ConfigureAwait(false)
					? await InternalAPIs.Cache.GetAsync<int>("Attempt#" + requestInfo.Session.IP).ConfigureAwait(false)
					: 0;
				attempt++;

				await Task.WhenAll(
					Task.Delay(567 + ((attempt - 1) * 5678)),
					InternalAPIs.Cache.SetAsync("Attempt#" + requestInfo.Session.IP, attempt)
				).ConfigureAwait(false);

				// show error
				context.WriteError(InternalAPIs.Logger, ex, requestInfo);
			}
		}
		#endregion

		#region Validate an OTP session
		static async Task ValidateOTPSessionAsync(this HttpContext context, RequestInfo requestInfo)
		{
			try
			{
				// prepare
				var body = requestInfo.GetBodyExpando();
				var id = body.Get<string>("ID");
				var otp = body.Get<string>("OTP");
				var info = body.Get<string>("Info");

				if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(otp) || string.IsNullOrWhiteSpace(info))
					throw new InvalidTokenException("OTP is invalid (empty)");

				// decrypt
				try
				{
					id = Global.RSA.Decrypt(id);
					otp = Global.RSA.Decrypt(otp);
					info = Global.RSA.Decrypt(info);
				}
				catch (Exception ex)
				{
					throw new InvalidTokenException("OTP is invalid (cannot decrypt)", ex);
				}

				// call service to validate
				var json = await context.CallServiceAsync(new RequestInfo(requestInfo.Session)
				{
					ServiceName = "Users",
					ObjectName = "OTP",
					Verb = "POST",
					Body = new JObject
					{
						{ "ID", id.Encrypt(Global.EncryptionKey) },
						{ "OTP", otp.Encrypt(Global.EncryptionKey) },
						{ "Info", info.Encrypt(Global.EncryptionKey) }
					}.ToString(Formatting.None),
					CorrelationID = requestInfo.CorrelationID
				}, Global.CancellationTokenSource.Token, InternalAPIs.Logger).ConfigureAwait(false);

				// register new session
				var oldSessionID = requestInfo.Session.SessionID;
				requestInfo.Session.User = json.FromJson<User>();
				requestInfo.Session.User.SessionID = requestInfo.Session.SessionID = UtilityService.NewUUID;
				await context.CreateSessionAsync(requestInfo, true).ConfigureAwait(false);

				// response
				json = new JObject
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "DeviceID", requestInfo.Session.DeviceID }
				};
				context.UpdateSessionJson(requestInfo.Session, json);

				// response
				await Task.WhenAll(
					context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
					InternalAPIs.Cache.RemoveAsync("Attempt#" + requestInfo.Session.IP),
					InternalAPIs.Cache.RemoveAsync($"Session#{oldSessionID}"),
					!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(InternalAPIs.Logger, "InternalAPIs", new List<string>
					{
						$"Successfully process request of session (OTP validation)",
						$"Request: {requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"Response: {json.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"Execution times: {context.GetExecutionTimes()}"
					})
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				// wait
				var attempt = await InternalAPIs.Cache.ExistsAsync("Attempt#" + requestInfo.Session.IP).ConfigureAwait(false)
					? await InternalAPIs.Cache.GetAsync<int>("Attempt#" + requestInfo.Session.IP).ConfigureAwait(false)
					: 0;
				attempt++;

				await Task.WhenAll(
					Task.Delay(567 + ((attempt - 1) * 5678)),
					InternalAPIs.Cache.SetAsync("Attempt#" + requestInfo.Session.IP, attempt)
				).ConfigureAwait(false);

				// show error
				context.WriteError(InternalAPIs.Logger, ex, requestInfo);
			}
		}
		#endregion

		#region Sign a session out
		static async Task SignSessionOutAsync(this HttpContext context, RequestInfo requestInfo)
		{
			try
			{
				// check
				if (requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.IsSystemAccount)
					throw new InvalidRequestException();

				// call service to perform sign out
				await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "DELETE", requestInfo.Query, requestInfo.Header)
				{
					Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "Signature", requestInfo.Header["x-app-token"].GetHMACSHA256(Global.ValidationKey) }
					},
					CorrelationID = requestInfo.CorrelationID
				}, Global.CancellationTokenSource.Token, InternalAPIs.Logger).ConfigureAwait(false);

				// send update message
				await requestInfo.Session.SendOnlineStatusAsync(false).ConfigureAwait(false);

				// create & register the new session of visitor
				var oldSessionID = requestInfo.Session.SessionID;
				requestInfo.Session.SessionID = UtilityService.NewUUID;
				requestInfo.Session.User = new User("", requestInfo.Session.SessionID, new List<string> { SystemRole.All.ToString() }, new List<Privilege>());
				await context.CreateSessionAsync(requestInfo).ConfigureAwait(false);

				// response
				var json = new JObject
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "DeviceID", requestInfo.Session.DeviceID }
				};
				context.UpdateSessionJson(requestInfo.Session, json);

				await Task.WhenAll(
					context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
					InternalAPIs.Cache.RemoveAsync($"Session#{oldSessionID}"),
					InternalAPIs.Cache.SetAsync($"Session#{requestInfo.Session.SessionID}", requestInfo.Session.SessionID.Encrypt(Global.EncryptionKey), 7),
					!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(InternalAPIs.Logger, "InternalAPIs", new List<string>
					{
						$"Successfully process request of session (sign-out)",
						$"Request: {requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"Response: {json.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"Execution times: {context.GetExecutionTimes()}"
					})
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				context.WriteError(InternalAPIs.Logger, ex, requestInfo);
			}
		}
		#endregion

		#region Activation
		static async Task ActivateAsync(this HttpContext context, RequestInfo requestInfo)
		{
			// call service to activate
			var json = await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Activate", "GET", requestInfo.Query, requestInfo.Header, "", requestInfo.Extra, requestInfo.CorrelationID), Global.CancellationTokenSource.Token, InternalAPIs.Logger).ConfigureAwait(false);

			// get user information & register the session
			requestInfo.Session.User = json.FromJson<User>();
			requestInfo.Session.User.SessionID = requestInfo.Session.SessionID = UtilityService.NewUUID;
			await context.CreateSessionAsync(requestInfo).ConfigureAwait(false);

			// response
			json = new JObject
			{
				{ "ID", requestInfo.Session.SessionID },
				{ "DeviceID", requestInfo.Session.DeviceID }
			};
			context.UpdateSessionJson(requestInfo.Session, json);

			await Task.WhenAll(
				context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
				!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(InternalAPIs.Logger, "InternalAPIs", new List<string>
				{
						$"Successfully process request of session (activation)",
						$"Request: {requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"Response: {json.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"Execution times: {context.GetExecutionTimes()}"
				})
			).ConfigureAwait(false);
		}
		#endregion

		#region Heper: keys, session, online status, ...
		internal static byte[] GetEncryptionKey(this string sessionID)
			=> sessionID.GetHMACHash(Global.EncryptionKey, "SHA512").GenerateHashKey(256);

		internal static byte[] GetEncryptionIV(this string sessionID)
			=> sessionID.GetHMACHash(Global.EncryptionKey, "SHA256").GenerateHashKey(128);

		internal static byte[] GetEncryptionKey(this string sessionID, IDictionary<object, object> items)
			=> items != null
				? items.ContainsKey("EncryptionKey")
					? items["EncryptionKey"] as byte[]
					: (items["EncryptionKey"] = sessionID.GetEncryptionKey()) as byte[]
				: sessionID.GetEncryptionKey();

		internal static byte[] GetEncryptionIV(this string sessionID, IDictionary<object, object> items)
			=> items != null
				? items.ContainsKey("EncryptionIV")
					? items["EncryptionIV"] as byte[]
					: (items["EncryptionIV"] = sessionID.GetEncryptionIV()) as byte[]
				: sessionID.GetEncryptionIV();

		internal static byte[] GetEncryptionKey(this HttpContext context, Session session) => session.SessionID.GetEncryptionKey(context.Items);

		internal static byte[] GetEncryptionIV(this HttpContext context, Session session) => session.SessionID.GetEncryptionIV(context.Items);

		internal static byte[] GetEncryptionKey(this Session session, IDictionary<object, object> items) => session.SessionID.GetEncryptionKey(items);

		internal static byte[] GetEncryptionIV(this Session session, IDictionary<object, object> items) => session.SessionID.GetEncryptionIV(items);

		internal static string GetEncryptedID(this string sessionID) => sessionID.HexToBytes().Encrypt(Global.EncryptionKey.GetEncryptionKey(), Global.ValidationKey.GetEncryptionIV()).ToHex();

		internal static string GetDecryptedID(this string sessionID) => sessionID.HexToBytes().Decrypt(Global.EncryptionKey.GetEncryptionKey(), Global.ValidationKey.GetEncryptionIV()).ToHex();

		internal static void UpdateSessionJson(this Session session, JObject json, IDictionary<object, object> items)
		{
			json["ID"] = session.SessionID.GetEncryptedID();
			json["Keys"] = new JObject
			{
				{
					"RSA",
					new JObject
					{
						{ "Exponent", Global.RSAExponent },
						{ "Modulus", Global.RSAModulus }
					}
				},
				{
					"AES",
					new JObject
					{
						{ "Key", session.GetEncryptionKey(items).ToHex() },
						{ "IV", session.GetEncryptionIV(items).ToHex() }
					}
				},
				{
					"JWT",
					Global.JWTKey
				}
			};
			json["Token"] = session.GetAuthenticateToken();
		}

		internal static void UpdateSessionJson(this HttpContext context, Session session, JObject json) => session.UpdateSessionJson(json, context.Items);

		internal static Task SendOnlineStatusAsync(this Session session, bool isOnline)
		{
			return session.User == null || session.User.ID.Equals("") || session.User.IsSystemAccount
				? Task.CompletedTask
				: new CommunicateMessage("Users")
				{
					Type = "OnlineStatus",
					Data = new JObject
					{
						{ "UserID", session.User.ID },
						{ "SessionID", session.SessionID },
						{ "DeviceID", session.DeviceID },
						{ "AppName", session.AppName },
						{ "AppPlatform", session.AppPlatform },
						{ "IP", session.IP },
						{ "IsOnline", isOnline },
					}
				}.PublishAsync(RTU.Logger);
		}
		#endregion

		#region Helper: WAMP connections & real-time updaters
		internal static void OpenWAMPChannels(int waitingTimes = 6789)
		{
			var routerInfo = WAMPConnections.GetRouterInfo();
			Global.Logger.LogInformation($"Attempting to connect to WAMP router [{routerInfo.Item1}{(routerInfo.Item1.EndsWith("/") ? "" : "/")}{routerInfo.Item2}]");
			Global.OpenWAMPChannels(
				(sender, args) =>
				{
					Global.Logger.LogInformation($"Incomming channel to WAMP router is established - Session ID: {args.SessionId}");
					Global.InterCommunicateMessageUpdater?.Dispose();
					Global.InterCommunicateMessageUpdater = WAMPConnections.IncommingChannel.RealmProxy.Services
						.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages.apigateway")
						.Subscribe(
							async (message) =>
							{
								try
								{
									await InternalAPIs.ProcessInterCommunicateMessageAsync(message).ConfigureAwait(false);
									if (Global.IsDebugLogEnabled)
										await Global.WriteLogsAsync(RTU.Logger, "RTU", $"Process an inter-communicate message successful {message?.ToJson().ToString(Formatting.Indented)}").ConfigureAwait(false);
								}
								catch (Exception ex)
								{
									await Global.WriteLogsAsync(RTU.Logger, "RTU", $"{ex.Message} => {message?.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}", ex).ConfigureAwait(false);
								}
							},
							exception => Global.WriteLogs(RTU.Logger, "RTU", $"{exception.Message}", exception)
						);
				},
				(sender, args) =>
				{
					Global.Logger.LogInformation($"Outgoing channel to WAMP router is established - Session ID: {args.SessionId}");
					try
					{
						Task.WaitAll(new[] { Global.InitializeLoggingServiceAsync(), Global.InitializeRTUServiceAsync() }, waitingTimes > 0 ? waitingTimes : 6789, Global.CancellationTokenSource.Token);
						Global.Logger.LogInformation("Helper services are succesfully initialized");
					}
					catch (Exception ex)
					{
						Global.Logger.LogError($"Error occurred while initializing helper services: {ex.Message}", ex);
					}
				},
				waitingTimes
			);
		}

		internal static async Task ProcessInterCommunicateMessageAsync(CommunicateMessage message)
		{
			// update users' sessions with new access token
			if (message.Type.Equals("Session#Update"))
			{
				// prepare
				var sessionID = message.Data.Get<string>("Session");
				var user = message.Data.Get<JObject>("User").FromJson<User>();
				var deviceID = message.Data.Get<string>("Device");
				var verification = message.Data.Get<bool>("Verification");

				var json = new JObject
				{
					{ "ID", sessionID },
					{ "UserID", user.ID },
					{ "DeviceID", deviceID }
				};

				new Session
				{
					SessionID = sessionID,
					DeviceID = deviceID,
					User = user,
					Verification = verification
				}.UpdateSessionJson(json, Global.CurrentHttpContext?.Items);

				// send update message
				await new UpdateMessage
				{
					Type = "Users#Session#Update",
					DeviceID = deviceID,
					Data = json
				}.PublishAsync(RTU.Logger).ConfigureAwait(false);
			}

			// revoke users' sessions
			else if (message.Type.Equals("Session#Revoke"))
			{
				// prepare
				var sessionID = message.Data.Get<string>("Session");
				var user = message.Data.Get<JObject>("User").FromJson<User>();
				var deviceID = message.Data.Get<string>("Device");

				var json = new JObject
				{
					{ "ID", sessionID },
					{ "UserID", user.ID },
					{ "DeviceID", deviceID },
				};

				new Session
				{
					SessionID = sessionID,
					DeviceID = deviceID,
					User = user
				}.UpdateSessionJson(json, Global.CurrentHttpContext?.Items);

				// send update message
				await new UpdateMessage
				{
					Type = "Users#Session#Revoke",
					DeviceID = deviceID,
					Data = json
				}.PublishAsync(RTU.Logger).ConfigureAwait(false);
			}
		}
		#endregion

	}
}