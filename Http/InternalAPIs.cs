#region Related components
using System;
using System.IO;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Reactive.Subjects;

using Microsoft.AspNetCore.Http;

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
		internal static Cache Cache { get; set; }
		internal static List<string> ExcludedHeaders { get; } = "connection,accept,accept-encoding,accept-language,cache-control,cookie,content-type,content-length,user-agent,referer,host,origin,if-modified-since,if-none-match,upgrade-insecure-requests,ms-aspnetcore-token,x-original-proto,x-original-for".ToList();

		internal static async Task ProcessRequestAsync(HttpContext context)
		{
			#region prepare the requesting information			
			var requestUri = context.GetRequestUri();

			var queryString = requestUri.ParseQuery(query =>
			{
				var executionFilePath = requestUri.PathAndQuery;
				if (executionFilePath.IndexOf("?") > 0)
					executionFilePath = executionFilePath.Left(executionFilePath.IndexOf("?"));
				if (executionFilePath.Equals("~/") || executionFilePath.Equals("/"))
					executionFilePath = "";
				var executionFilePaths = string.IsNullOrWhiteSpace(executionFilePath)
					? new[] { "" }
					: executionFilePath.ToLower().ToArray('/', true);
				query["service-name"] = !string.IsNullOrWhiteSpace(executionFilePaths[0]) ? executionFilePaths[0].GetANSIUri() : "";
				query["object-name"] = executionFilePaths.Length > 1 && !string.IsNullOrWhiteSpace(executionFilePaths[1]) ? executionFilePaths[1].GetANSIUri() : "";
				query["object-identity"] = executionFilePaths.Length > 2 && !string.IsNullOrWhiteSpace(executionFilePaths[2]) ? executionFilePaths[2].GetANSIUri() : "";
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
				var tokenIsRequired = isActivationProccessed
					? false
					: isSessionInitialized && (requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.IsSystemAccount) && !requestInfo.Query.ContainsKey("register")
						? false
						: requestInfo.ServiceName.IsEquals("indexes")
							? false
							: true;

				// parse and update information from token
				var appToken = requestInfo.GetParameter("x-app-token");
				if (!string.IsNullOrWhiteSpace(appToken))
				{
					requestInfo.Header["x-app-token"] = appToken;
					await context.UpdateWithAuthenticateTokenAsync(requestInfo.Session, appToken).ConfigureAwait(false);
				}
				else if (tokenIsRequired)
					throw new InvalidSessionException("Session is invalid (Token is not found)");

				// check existed of session
				if (tokenIsRequired && !await context.CheckSessionExistAsync(requestInfo.Session).ConfigureAwait(false))
					throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
			}
			catch (Exception ex)
			{
				context.WriteError(ex, requestInfo, null, false);
				return;
			}
			#endregion

			#region prepare others (session identity, user principal, request body)
			// new session
			if (string.IsNullOrWhiteSpace(requestInfo.Session.SessionID))
			{
				requestInfo.Session.SessionID = UtilityService.NewUUID;
				requestInfo.Session.User.SessionID = requestInfo.Session.SessionID;
			}

			// request body
			if (requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT"))
				try
				{
					requestInfo.Body = await context.ReadTextAsync(Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					await context.WriteLogsAsync("InternalAPIs", "Error occurred while parsing body of the request", ex).ConfigureAwait(false);
				}

			else if (requestInfo.Verb.IsEquals("GET") && requestInfo.Query.ContainsKey("x-body"))
				try
				{
					requestInfo.Body = requestInfo.Query["x-body"].Url64Decode();
				}
				catch (Exception ex)
				{
					await context.WriteLogsAsync("InternalAPIs", "Error occurred while parsing body of the 'x-body' parameter", ex).ConfigureAwait(false);
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
						registered = registered.Decrypt(context.GetEncryptionKey(requestInfo.Session), context.GetEncryptionIV(requestInfo.Session));
						input = input.Decrypt(context.GetEncryptionKey(requestInfo.Session), context.GetEncryptionIV(requestInfo.Session));
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
					context.WriteError(ex, requestInfo, null, false);
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
							requestInfo.Extra = new Dictionary<string, string>(requestInfo.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
							{
								{ "Email", email.Encrypt(Global.EncryptionKey) }
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
							password = Global.RSA.Decrypt(password);
							requestInfo.Extra = new Dictionary<string, string>(requestInfo.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
							{
								{ "Password", password.Encrypt(Global.EncryptionKey) }
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
							oldPassword = Global.RSA.Decrypt(oldPassword);
							requestInfo.Extra = new Dictionary<string, string>(requestInfo.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
							{
								{ "OldPassword", oldPassword.Encrypt(Global.EncryptionKey) }
							};
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
							requestInfo.Extra = new Dictionary<string, string>(requestInfo.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
							{
								{ "Roles", Global.RSA.Decrypt(roles).Encrypt(Global.EncryptionKey) }
							};
						}
						catch { }

					// prepare privileges
					var privileges = requestBody.Get<string>("Privileges");
					if (!string.IsNullOrWhiteSpace(privileges))
						try
						{
							requestInfo.Extra = new Dictionary<string, string>(requestInfo.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
							{
								{ "Privileges", Global.RSA.Decrypt(privileges).Encrypt(Global.EncryptionKey) }
							};
						}
						catch { }

					// prepare information of related service
					var relatedInfo = requestInfo.Query.ContainsKey("related-service")
						? requestBody.Get<string>("RelatedInfo")
						: null;
					if (!string.IsNullOrWhiteSpace(relatedInfo))
						try
						{
							relatedInfo = Global.RSA.Decrypt(relatedInfo);
							requestInfo.Extra = new Dictionary<string, string>(requestInfo.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
							{
								{ "RelatedInfo", relatedInfo.Encrypt(Global.EncryptionKey) }
							};
						}
						catch { }

					// preapare
					var objectIdentity = requestInfo.GetObjectIdentity();

					// prepare to register/create new account
					if (string.IsNullOrWhiteSpace(objectIdentity))
					{
						if (!captchaIsValid)
							throw new InvalidSessionException("Captcha code is invalid");

						var requestCreateAccount = requestInfo.GetHeaderParameter("x-create");
						if (!string.IsNullOrWhiteSpace(requestCreateAccount) && requestCreateAccount.Equals(requestInfo.Session.SessionID.GetEncryptedID()))
							requestInfo.Extra = new Dictionary<string, string>(requestInfo.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
							{
								{ "x-create", "" }
							};
					}

					// prepare to invite
					else if ("invite".IsEquals(objectIdentity))
						requestInfo.Extra = new Dictionary<string, string>(requestInfo.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
						{
							{ "x-invite", "" }
						};

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
					context.WriteError(ex, requestInfo, null, false);
					return;
				}
			#endregion

			// set user principal
			context.User = new UserPrincipal(requestInfo.Session.User);

			// request of sessions
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

			// request of activations
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

			// request of services
			else
				try
				{
					var response = await context.CallServiceAsync(requestInfo, Global.CancellationTokenSource.Token).ConfigureAwait(false);
					await context.WriteAsync(response, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None, requestInfo.CorrelationID, Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(ex, requestInfo);
				}
		}

		#region Check existing of a session
		static async Task<bool> CheckSessionExistAsync(this HttpContext context, Session session)
		{
			if (string.IsNullOrWhiteSpace(session?.SessionID))
				return false;
			else if (await InternalAPIs.Cache.ExistsAsync($"Session#{session.SessionID}").ConfigureAwait(false))
				return true;
			else
			{
				if (await context.IsSessionExistAsync(session).ConfigureAwait(false))
				{
					var run = Task.Run(async () =>
					{
						if (!await InternalAPIs.Cache.ExistsAsync($"Session#{session.SessionID}").ConfigureAwait(false))
							await InternalAPIs.Cache.SetAsync($"Session#{session.SessionID}", session.SessionID.Encrypt(Global.EncryptionKey)).ConfigureAwait(false);
					}).ConfigureAwait(false);
					return true;
				}
				{
					var run = Task.Run(async () =>
					{
						if (await InternalAPIs.Cache.ExistsAsync($"Session#{session.SessionID}").ConfigureAwait(false))
							await InternalAPIs.Cache.RemoveAsync($"Session#{session.SessionID}").ConfigureAwait(false);
					}).ConfigureAwait(false);
					return false;
				}
			}
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
						!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync("InternalAPIs", new List<string>
						{
							$"<REST> Successfully process request of session (anonymous registration)",
							$"Request:\r\n{requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
							$"Response:\r\n{json.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
							$"Execution times: {context.GetExecutionTimes()}"
						})
					).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(ex, requestInfo);
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
					}, Global.CancellationTokenSource.Token).ConfigureAwait(false);

					// check
					if (session == null)
						throw new SessionNotFoundException();
					else if (!requestInfo.Session.User.ID.IsEquals(session.Get<string>("UserID")))
						throw new InvalidTokenException();

					// update session
					session["RenewedAt"] = DateTime.Now;
					session["ExpiredAt"] = DateTime.Now.AddDays(60);
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
					}, Global.CancellationTokenSource.Token).ConfigureAwait(false);

					// response
					var json = new JObject
					{
						{ "ID", requestInfo.Session.SessionID },
						{ "DeviceID", requestInfo.Session.DeviceID }
					};
					context.UpdateSessionJson(requestInfo.Session, json);

					await Task.WhenAll(
						context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
						!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync("InternalAPIs", new List<string>
						{
							$"<REST> Successfully process request of session (authenticated user registration)",
							$"Request:\r\n{requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
							$"Response:\r\n{json.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
							$"Execution times: {context.GetExecutionTimes()}"
						})
					).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(ex, requestInfo);
				}
		}
		#endregion

		#region Create a session
		static JObject GenerateSessionJson(this RequestInfo requestInfo, bool is2FAVerified = false, bool isOnline = true)
			=> new JObject
			{
				{ "ID", requestInfo.Session.SessionID },
				{ "IssuedAt", DateTime.Now },
				{ "RenewedAt", DateTime.Now },
				{ "ExpiredAt", DateTime.Now.AddDays(60) },
				{ "UserID", requestInfo.Session.User.ID },
				{ "AccessToken", requestInfo.Session.User.GetAccessToken(Global.ECCKey) },
				{ "IP", requestInfo.Session.IP },
				{ "DeviceID", requestInfo.Session.DeviceID },
				{ "AppInfo", requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform },
				{ "OSInfo", $"{requestInfo.Session.AppAgent.GetOSInfo()} [{requestInfo.Session.AppAgent}]" },
				{ "Verification", is2FAVerified },
				{ "Online", isOnline }
			};

		static async Task CreateSessionAsync(this HttpContext context, RequestInfo requestInfo, bool is2FAVerified = false)
		{
			var body = requestInfo.GenerateSessionJson(is2FAVerified).ToString(Formatting.None);
			await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "POST")
			{
				Body = body,
				Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
				{
					{ "Signature", body.GetHMACSHA256(Global.ValidationKey) }
				},
				CorrelationID = requestInfo.CorrelationID
			}, Global.CancellationTokenSource.Token).ConfigureAwait(false);

			await requestInfo.Session.SendOnlineStatusAsync(true).ConfigureAwait(false);
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
				var json = await context.CallServiceAsync(new RequestInfo(requestInfo.Session)
				{
					ServiceName = "Users",
					ObjectName = "Session",
					Verb = "PUT",
					Body = body,
					Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "Signature", body.GetHMACSHA256(Global.ValidationKey) }
					},
					CorrelationID = requestInfo.CorrelationID
				}, Global.CancellationTokenSource.Token).ConfigureAwait(false);

				// two-factors authentication
				var oldSessionID = string.Empty;
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
					oldSessionID = requestInfo.Session.SessionID;
					requestInfo.Session.SessionID = UtilityService.NewUUID;
					requestInfo.Session.User = json.FromJson<User>();
					requestInfo.Session.User.SessionID = requestInfo.Session.SessionID;
					await context.CreateSessionAsync(requestInfo).ConfigureAwait(false);

					// response
					json = new JObject()
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
					!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync("InternalAPIs", new List<string>
					{
						$"<REST> Successfully process request of session (sign-in)",
						$"Request:\r\n{requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"Response:\r\n{json.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
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
				context.WriteError(ex, requestInfo);
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
				if (body == null)
					throw new InvalidTokenException("OTP is invalid (empty)");

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
					Body = new JObject()
					{
						{ "ID", id.Encrypt(Global.EncryptionKey) },
						{ "OTP", otp.Encrypt(Global.EncryptionKey) },
						{ "Info", info.Encrypt(Global.EncryptionKey) }
					}.ToString(Formatting.None),
					CorrelationID = requestInfo.CorrelationID
				}, Global.CancellationTokenSource.Token).ConfigureAwait(false);

				// register new session
				var oldSessionID = requestInfo.Session.SessionID;
				requestInfo.Session.User = json.FromJson<User>();
				requestInfo.Session.SessionID = UtilityService.NewUUID;
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
					!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync("InternalAPIs", new List<string>
					{
						$"<REST> Successfully process request of session (OTP validation)",
						$"Request:\r\n{requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"Response:\r\n{json.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
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
				context.WriteError(ex, requestInfo);
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
				}, Global.CancellationTokenSource.Token).ConfigureAwait(false);

				// send update message
				await requestInfo.Session.SendOnlineStatusAsync(false).ConfigureAwait(false);

				// create & register the new session of visitor
				var oldSessionID = requestInfo.Session.SessionID;
				requestInfo.Session.SessionID = UtilityService.NewUUID;
				requestInfo.Session.User = new User("", requestInfo.Session.SessionID, new List<string> { SystemRole.All.ToString() }, new List<Privilege>());
				await context.CreateSessionAsync(requestInfo).ConfigureAwait(false);

				// response
				var json = new JObject()
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "DeviceID", requestInfo.Session.DeviceID }
				};
				context.UpdateSessionJson(requestInfo.Session, json);

				await Task.WhenAll(
					context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
					InternalAPIs.Cache.RemoveAsync($"Session#{oldSessionID}"),
					!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync("InternalAPIs", new List<string>
					{
						$"<REST> Successfully process request of session (sign-out)",
						$"Request:\r\n{requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"Response:\r\n{json.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"Execution times: {context.GetExecutionTimes()}"
					})
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				context.WriteError(ex, requestInfo);
			}
		}
		#endregion

		#region Activation
		static async Task ActivateAsync(this HttpContext context, RequestInfo requestInfo)
		{
			// call service to activate
			var json = await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Activate", "GET", requestInfo.Query, requestInfo.Header, "", requestInfo.Extra, requestInfo.CorrelationID)).ConfigureAwait(false);

			// get user information & register the session
			requestInfo.Session.User = json.FromJson<User>();
			var body = requestInfo.GenerateSessionJson().ToString(Formatting.None);
			await Task.WhenAll(
				context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "POST")
				{
					Body = body,
					Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "Signature", body.GetHMACSHA256(Global.ValidationKey) }
					},
					CorrelationID = requestInfo.CorrelationID
				}, Global.CancellationTokenSource.Token),
				requestInfo.Session.SendOnlineStatusAsync(true)
			).ConfigureAwait(false);

			// response
			json = new JObject()
			{
				{ "ID", requestInfo.Session.SessionID },
				{ "DeviceID", requestInfo.Session.DeviceID }
			};
			context.UpdateSessionJson(requestInfo.Session, json);

			await Task.WhenAll(
				context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
				!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync("InternalAPIs", new List<string>
				{
						$"<REST> Successfully process request of session (activation)",
						$"Request:\r\n{requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"Response:\r\n{json.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"Execution times: {context.GetExecutionTimes()}"
				})
			).ConfigureAwait(false);
		}
		#endregion

		#region Heper: keys, session, online status, ...
		internal static byte[] GetEncryptionKey(this Session session) => session.SessionID.GetHMACHash(Global.EncryptionKey, "SHA512").GenerateHashKey(256);

		internal static byte[] GetEncryptionIV(this Session session) => session.SessionID.GetHMACHash(Global.EncryptionKey, "SHA256").GenerateHashKey(128);

		internal static byte[] GetEncryptionKey(this HttpContext context, Session session)
			=> context.Items.ContainsKey("EncryptionKey")
				? context.Items["EncryptionKey"] as byte[]
				: (context.Items["EncryptionKey"] = session.GetEncryptionKey()) as byte[];

		internal static byte[] GetEncryptionIV(this HttpContext context, Session session)
			=> context.Items.ContainsKey("EncryptionIV")
				? context.Items["EncryptionIV"] as byte[]
				: (context.Items["EncryptionIV"] = session.GetEncryptionIV()) as byte[];

		static string GetEncryptedID(this string sessionID) => sessionID.HexToBytes().Encrypt(Global.EncryptionKey.Reverse().GenerateHashKey(256), Global.EncryptionKey.GenerateHashKey(128)).ToHex();

		static string GetDecryptedID(this string sessionID) => sessionID.HexToBytes().Decrypt(Global.EncryptionKey.Reverse().GenerateHashKey(256), Global.EncryptionKey.GenerateHashKey(128)).ToHex();

		internal static void UpdateSessionJson(this HttpContext context, Session session, JObject json)
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
						{ "Key", context.GetEncryptionKey(session).ToHex() },
						{ "IV", context.GetEncryptionIV(session).ToHex() }
					}
				},
				{
					"JWT",
					Global.JWTKey
				}
			};
			json["Token"] = session.GetAuthenticateToken();
		}

		internal static Task SendOnlineStatusAsync(this Session session, bool isOnline)
		{
			return session.User == null || session.User.ID.Equals("") || session.User.IsSystemAccount
				? Task.CompletedTask
				: InternalAPIs.SendInterCommunicateMessageAsync(new CommunicateMessage("Users")
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
				});
		}
		#endregion

		#region Helper: WAMP connections & real-time updaters
		internal static void OpenWAMPChannels(int waitingTimes = 6789)
		{
			var routerInfo = WAMPConnections.GetRouterInfo();
			Global.Logger.LogInformation($"Attempting to connect to WAMP router [{routerInfo.Item1}{routerInfo.Item2}]");
			Global.OpenWAMPChannels(
				(sender, args) =>
				{
					Global.Logger.LogInformation($"Incomming channel to WAMP router is established - Session ID: {args.SessionId}");
					InternalAPIs.InterCommunicateMessageUpdater = WAMPConnections.IncommingChannel.RealmProxy.Services
						.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages.apigateway")
						.Subscribe(
							async (message) =>
							{
								try
								{
									await InternalAPIs.ProcessInterCommunicateMessageAsync(message).ConfigureAwait(false);
									if (Global.IsDebugLogEnabled)
										await Global.WriteLogsAsync("InternalAPIs", $"<RTU> Process an inter-communicate message successful\r\n{message?.ToJson().ToString(Formatting.Indented)}").ConfigureAwait(false);
								}
								catch (Exception ex)
								{
									await Global.WriteLogsAsync("InternalAPIs", $"<RTU> {ex.Message} => {message?.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}", ex).ConfigureAwait(false);
								}
							},
							exception => Global.WriteLogs("InternalAPIs", $"<RTU> {exception.Message}", exception)
						);
				},
				(sender, args) =>
				{
					Global.Logger.LogInformation($"Outgoing channel to WAMP router is established - Session ID: {args.SessionId}");
					try
					{
						Task.WaitAll(new[] { Global.InitializeLoggingServiceAsync(), Global.InitializeRTUServiceAsync() }, waitingTimes > 0 ? waitingTimes : 6789, Global.CancellationTokenSource.Token);
						Global.Logger.LogInformation("Helper services succesfully initialized");
					}
					catch (Exception ex)
					{
						Global.Logger.LogError($"Error occurred while initializing helper services: {ex.Message}", ex);
					}
				},
				waitingTimes
			);
		}

		static ISubject<UpdateMessage> UpdateMessagePublisher = null;
		static IDisposable InterCommunicateMessageUpdater = null;

		internal static async Task SendInterCommunicateMessageAsync(CommunicateMessage message)
		{
			try
			{
				await Global.RTUService.SendInterCommunicateMessageAsync(message, Global.CancellationTokenSource.Token).ConfigureAwait(false);
				if (Global.IsDebugResultsEnabled)
					await Global.WriteLogsAsync("InternalAPIs", $"<RTU> Send an inter-communicate message successful\r\n{message.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}").ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await Global.WriteLogsAsync("InternalAPIs", $"<RTU> {ex.Message}", ex).ConfigureAwait(false);
			}
		}

		internal static async Task ProcessInterCommunicateMessageAsync(CommunicateMessage message)
		{
			// update users' sessions with new access token
			if (message.Type.Equals("Session#Update"))
			{
				// prepare
				var sessionID = (message.Data["Session"] as JValue).Value as string;
				var user = (message.Data["User"] as JObject).FromJson<User>();
				var deviceID = (message.Data["Device"] as JValue).Value as string;
				var verification = (message.Data["Verification"] as JValue).Value.CastAs<bool>();

				var json = new JObject()
				{
					{ "ID", sessionID },
					{ "UserID", user.ID },
					{ "DeviceID", deviceID }
				};

				// update
				Global.CurrentHttpContext.UpdateSessionJson(new Session
				{
					SessionID = sessionID,
					DeviceID = deviceID,
					User = user,
					Verification = verification
				}, json);

				await new UpdateMessage
				{
					Type = "Users#Session#Update",
					DeviceID = deviceID,
					Data = json
				}.PublishAsync().ConfigureAwait(false);
			}

			// revoke users' sessions
			else if (message.Type.Equals("Session#Revoke"))
			{
				// prepare
				var sessionID = (message.Data["Session"] as JValue).Value as string;
				var user = (message.Data["User"] as JObject).FromJson<User>();
				var deviceID = (message.Data["Device"] as JValue).Value as string;

				var json = new JObject()
				{
					{ "ID", sessionID },
					{ "UserID", user.ID },
					{ "DeviceID", deviceID },
				};

				// update
				Global.CurrentHttpContext.UpdateSessionJson(new Session
				{
					SessionID = sessionID,
					DeviceID = deviceID,
					User = user
				}, json);

				await new UpdateMessage
				{
					Type = "Users#Session#Revoke",
					DeviceID = deviceID,
					Data = json
				}.PublishAsync().ConfigureAwait(false);
			}
		}

		internal static void Publish(this UpdateMessage message)
		{
			if (InternalAPIs.UpdateMessagePublisher == null)
				try
				{
					InternalAPIs.UpdateMessagePublisher = WAMPConnections.OutgoingChannel.RealmProxy.Services.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages");
					InternalAPIs.UpdateMessagePublisher.OnNext(message);
				}
				catch (Exception ex)
				{
					Global.WriteLogs("InternalAPIs", $"<RTU> {ex.Message} => {message.ToJson().ToString(Formatting.Indented)}", ex);
				}

			else
				try
				{
					InternalAPIs.UpdateMessagePublisher.OnNext(message);
				}
				catch (Exception ex)
				{
					Global.WriteLogs("InternalAPIs", $"<RTU> {ex.Message} => {message.ToJson().ToString(Formatting.Indented)}", ex);
				}
		}

		internal static async Task PublishAsync(this UpdateMessage message)
		{
			if (InternalAPIs.UpdateMessagePublisher == null)
				try
				{
					await WAMPConnections.OpenOutgoingChannelAsync().ConfigureAwait(false);
					InternalAPIs.UpdateMessagePublisher = WAMPConnections.OutgoingChannel.RealmProxy.Services.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages");
					InternalAPIs.UpdateMessagePublisher.OnNext(message);
				}
				catch (Exception ex)
				{
					await Global.WriteLogsAsync("InternalAPIs", $"<RTU> {ex.Message} => {message.ToJson().ToString(Formatting.Indented)}", ex).ConfigureAwait(false);
				}

			else
				try
				{
					InternalAPIs.UpdateMessagePublisher.OnNext(message);
				}
				catch (Exception ex)
				{
					await Global.WriteLogsAsync("InternalAPIs", $"<RTU> {ex.Message} => {message.ToJson().ToString(Formatting.Indented)}", ex).ConfigureAwait(false);
				}
		}
		#endregion

	}
}