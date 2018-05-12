#region Related components
using System;
using System.IO;
using System.Web;
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

		internal static async Task ProcessRequestAsync(HttpContext context)
		{
			// track
			var requestUri = context.GetRequestUri();
			await context.WriteLogsAsync("InternalAPIs", $"Begin process => {context.Request.Method} {requestUri.PathAndQuery}").ConfigureAwait(false);

			#region prepare the requesting information			
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

			var request = new RequestInfo()
			{
				Session = context.GetSession(),
				Verb = context.Request.Method,
				ServiceName = queryString["service-name"],
				ObjectName = queryString["object-name"],
				Query = queryString,
				Header = context.Request.Headers.ToNameValueCollection().ToDictionary(dictionary => "connection,accept,accept-encoding,accept-language,host,referer,user-agent,origin,cache-control,cookie,upgrade-insecure-requests,ms-aspnetcore-token,x-original-proto,x-original-for".ToList().ForEach(name => dictionary.Remove(name))),
				CorrelationID = context.GetCorrelationID()
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
			try
			{
				var tokenIsRequired = isActivationProccessed
					? false
					: isSessionInitialized && (request.Session.User.ID.Equals("") || request.Session.User.IsSystemAccount) && !request.Query.ContainsKey("register")
						? false
						: request.ServiceName.IsEquals("indexes")
							? false
							: true;

				// parse and update information from token
				var appToken = request.GetParameter("x-app-token");
				if (!string.IsNullOrWhiteSpace(appToken))
				{
					request.Header["x-app-token"] = appToken;
					await context.UpdateSessionAsync(request.Session, appToken, !request.Query.ContainsKey("register")).ConfigureAwait(false);
				}
				else if (tokenIsRequired)
					throw new InvalidSessionException("Session is invalid (Token is not found)");

				// check existed of session
				if (tokenIsRequired && !await context.CheckSessionExistAsync(request.Session).ConfigureAwait(false))
					throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
			}
			catch (Exception ex)
			{
				context.WriteError(ex, request, $"Error occurred while preparing token: {ex.Message}", false);
				return;
			}
			#endregion

			#region prepare others (session identity, user principal, request body)
			// new session
			if (string.IsNullOrWhiteSpace(request.Session.SessionID))
			{
				request.Session.SessionID = UtilityService.NewUUID;
				request.Session.User.SessionID = request.Session.SessionID;
			}

			// user principal
			context.User = new UserPrincipal(request.Session.User);

			// request body
			if (request.Verb.IsEquals("POST") || request.Verb.IsEquals("PUT"))
				try
				{
					request.Body = await context.ReadTextAsync().ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					await context.WriteLogsAsync("InternalAPIs", "Error occurred while parsing body of the request", ex).ConfigureAwait(false);
				}

			else if (request.Verb.IsEquals("GET") && request.Query.ContainsKey("x-body"))
				try
				{
					request.Body = request.Query["x-body"].Url64Decode();
				}
				catch (Exception ex)
				{
					await context.WriteLogsAsync("InternalAPIs", "Error occurred while parsing body of the 'x-body' parameter", ex).ConfigureAwait(false);
				}
			#endregion

			#region [extra] verify captcha
			// verfy captcha
			var captchaIsValid = false;
			if (request.Header.ContainsKey("x-captcha"))
				try
				{
					request.Header.TryGetValue("x-captcha-registered", out string registered);
					request.Header.TryGetValue("x-captcha-input", out string input);
					if (string.IsNullOrWhiteSpace(registered) || string.IsNullOrWhiteSpace(input))
						throw new InvalidSessionException("Captcha code is invalid");

					try
					{
						registered = registered.Decrypt(request.Session.GetEncryptionKey(), request.Session.GetEncryptionIV());
						input = input.Decrypt(request.Session.GetEncryptionKey(), request.Session.GetEncryptionIV());
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
					context.WriteError(ex, request, $"Error occurred while verifying captcha: {ex.Message}");
					return;
				}
			#endregion

			#region [extra] prepare information of an account
			if (isAccountProccessed)
				try
				{
					var requestBody = request.GetBodyExpando();
					if (requestBody == null)
						throw new InvalidSessionException("Request JSON is invalid (empty)");

					// prepare email
					var email = requestBody.Get<string>("Email");
					if (!string.IsNullOrWhiteSpace(email))
						try
						{
							email = Global.RSA.Decrypt(email);
							request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
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
							request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
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
							request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
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
							request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
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
							request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
							{
								{ "Privileges", Global.RSA.Decrypt(privileges).Encrypt(Global.EncryptionKey) }
							};
						}
						catch { }

					// prepare information of related service
					var relatedInfo = request.Query.ContainsKey("related-service")
						? requestBody.Get<string>("RelatedInfo")
						: null;
					if (!string.IsNullOrWhiteSpace(relatedInfo))
						try
						{
							relatedInfo = Global.RSA.Decrypt(relatedInfo);
							request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
							{
								{ "RelatedInfo", relatedInfo.Encrypt(Global.EncryptionKey) }
							};
						}
						catch { }

					// preapare
					var objectIdentity = request.GetObjectIdentity();

					// prepare to register/create new account
					if (string.IsNullOrWhiteSpace(objectIdentity))
					{
						if (!captchaIsValid)
							throw new InvalidSessionException("Captcha code is invalid");

						if (request.Session.SessionID.Encrypt(Global.EncryptionKey.Reverse(), true).Equals(request.GetHeaderParameter("x-create")))
							request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
							{
								{ "x-create", "" }
							};
					}

					// prepare to invite
					else if ("invite".IsEquals(objectIdentity))
						request.Extra = new Dictionary<string, string>(request.Extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
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
					context.WriteError(ex, request, $"Error occurred while processing account: {ex.Message}");
					return;
				}
			#endregion

			if (Global.IsDebugLogEnabled)
				await context.WriteLogsAsync("InternalAPIs", $"Begin process => Request:\r\n{request.ToJson().ToString(Formatting.Indented)}").ConfigureAwait(false);

			// process the request of session
			if (isSessionProccessed)
				switch (request.Verb)
				{
					case "GET":
						await InternalAPIs.RegisterSessionAsync(context, request).ConfigureAwait(false);
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
						context.WriteError(new MethodNotAllowedException(request.Verb), request, $"Method {request.Verb} is not allowed",false);
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
					context.WriteError(ex, request, $"Error occurred while activating: {ex.Message}");
				}
			}

			// process the request of services
			else
				try
				{
					var response = await context.CallServiceAsync(request).ConfigureAwait(false);
					await context.WriteAsync(response, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(ex, request, $"Error [{request.ServiceName}/{request.ObjectName}] => {ex.Message}");
				}
		}

		#region Check existing of a session
		static async Task<bool> CheckSessionExistAsync(this HttpContext context, Session session)
		{
			if (string.IsNullOrWhiteSpace(session?.SessionID))
				return false;
			else if (session.User.ID.Equals("") && await InternalAPIs.Cache.ExistsAsync($"Session#{session.SessionID}").ConfigureAwait(false))
				return true;
			else
				return await context.IsSessionExistAsync(session).ConfigureAwait(false);
		}
		#endregion

		#region Register a session
		static async Task RegisterSessionAsync(HttpContext context, RequestInfo requestInfo)
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
						await InternalAPIs.Cache.SetAsync($"Session#{requestInfo.Session.SessionID}", requestInfo.Session.SessionID.Encrypt(Global.EncryptionKey, true), 7).ConfigureAwait(false);
					}

					// register session
					else
					{
						// validate
						var register = requestInfo.Query["register"].Decrypt(Global.EncryptionKey.Reverse(), true);
						if (!requestInfo.Session.SessionID.IsEquals(register) || !register.Encrypt(Global.EncryptionKey, true).IsEquals(await InternalAPIs.Cache.GetAsync<string>($"Session#{requestInfo.Session.SessionID}").ConfigureAwait(false)))
							throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");

						// register with user service
						await Task.WhenAll(
							InternalAPIs.CreateSessionAsync(context, requestInfo),
							InternalAPIs.Cache.RemoveAsync($"Session#{requestInfo.Session.SessionID}")
						).ConfigureAwait(false);
					}

					// response
					var json = new JObject
					{
						{ "ID", requestInfo.Session.SessionID },
						{ "DeviceID", requestInfo.Session.DeviceID }
					};
					requestInfo.Session.UpdateSessionJson(json);

					await context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None).ConfigureAwait(false);
					if (Global.IsDebugLogEnabled && Global.IsDebugResultsEnabled)
						await context.WriteLogsAsync("InternalAPIs", $"End process => Response:\r\n{json.ToJson().ToString(Formatting.Indented)}").ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(ex, requestInfo, $"Error occurred while registering session: {ex.Message}");
				}

			// session of authenticated account
			else
				try
				{
					// call service to get session
					var session = await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "GET", requestInfo.Query, requestInfo.Header, null, new Dictionary<string, string>()
					{
						{ "Signature", requestInfo.Header["x-app-token"].GetHMACSHA256(Global.ValidationKey) }
					}, requestInfo.CorrelationID)).ConfigureAwait(false);
					var jsonUserID = session?["UserID"];
					var jsonAccessToken = session?["AccessToken"];

					// verify access token
					if (jsonUserID == null || !(jsonUserID is JValue) || (jsonUserID as JValue).Value == null || !requestInfo.Session.User.ID.Equals((jsonUserID as JValue).Value as string))
						throw new InvalidTokenException();

					// update session
					session["RenewedAt"] = DateTime.Now;
					session["ExpiredAt"] = DateTime.Now.AddDays(60);
					session["IP"] = requestInfo.Session.IP;
					session["DeviceID"] = requestInfo.Session.DeviceID;
					session["AppInfo"] = requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform;
					session["OSInfo"] = context.GetOSInfo() + $" [{context.Request.Headers["User-Agent"].First()}]";
					session["Online"] = true;

					// register with user service
					var body = session.ToString(Formatting.None);
					await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "POST")
					{
						Body = body,
						Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
						{
							{ "Signature", body.GetHMACSHA256(Global.ValidationKey) }
						},
						CorrelationID = requestInfo.CorrelationID
					}).ConfigureAwait(false);

					// response
					var json = new JObject
					{
						{ "ID", requestInfo.Session.SessionID },
						{ "DeviceID", requestInfo.Session.DeviceID }
					};
					requestInfo.Session.UpdateSessionJson(json);

					await context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None).ConfigureAwait(false);
					if (Global.IsDebugLogEnabled & Global.IsDebugResultsEnabled)
						await context.WriteLogsAsync("InternalAPIs", $"End process => Response:\r\n{json.ToJson().ToString(Formatting.Indented)}").ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(ex, requestInfo, $"Error occurred while registering session: {ex.Message}");
				}
		}
		#endregion

		#region Create a session
		static JObject GenerateSessionJson(RequestInfo requestInfo, bool is2FAVerified = false, bool isOnline = true)
		{
			return new JObject()
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
				{ "OSInfo", requestInfo.Header.ContainsKey("user-agent") ? requestInfo.Header["user-agent"].GetOSInfo() + " [" + requestInfo.Header["user-agent"] + "]" : "Unknown" },
				{ "Verification", is2FAVerified },
				{ "Online", isOnline }
			};
		}

		static async Task CreateSessionAsync(HttpContext context, RequestInfo requestInfo, bool is2FAVerified = false)
		{
			var body = InternalAPIs.GenerateSessionJson(requestInfo, is2FAVerified).ToString(Formatting.None);
			await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "POST")
			{
				Body = body,
				Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
				{
					{ "Signature", body.GetHMACSHA256(Global.ValidationKey) }
				},
				CorrelationID = requestInfo.CorrelationID
			}).ConfigureAwait(false);

			await requestInfo.Session.SendOnlineStatusAsync(true).ConfigureAwait(false);
		}
		#endregion

		#region Sign a session in
		static async Task SignSessionInAsync(HttpContext context, RequestInfo requestInfo)
		{
			try
			{
				// check
				if (!requestInfo.Session.SessionID.Encrypt(Global.EncryptionKey, true).IsEquals(await InternalAPIs.Cache.GetAsync<string>($"Session#{requestInfo.Session.SessionID}").ConfigureAwait(false)))
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
					await InternalAPIs.Cache.RemoveAsync($"Session#{requestInfo.Session.SessionID}").ConfigureAwait(false);

					requestInfo.Session.User = json.FromJson<UserIdentity>();
					requestInfo.Session.SessionID = UtilityService.NewUUID;
					await InternalAPIs.CreateSessionAsync(context, requestInfo).ConfigureAwait(false);

					// response
					json = new JObject()
					{
						{ "ID", requestInfo.Session.SessionID },
						{ "DeviceID", requestInfo.Session.DeviceID }
					};
					requestInfo.Session.UpdateSessionJson(json);
				}

				// response
				await Task.WhenAll(
					context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None),
					InternalAPIs.Cache.RemoveAsync("Attempt#" + requestInfo.Session.IP)
				).ConfigureAwait(false);
				if (Global.IsDebugLogEnabled && Global.IsDebugResultsEnabled)
					await context.WriteLogsAsync("InternalAPIs", $"End process => Response:\r\n{json.ToJson().ToString(Formatting.Indented)}").ConfigureAwait(false);
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
				context.WriteError(ex, requestInfo, $"Error occurred while signing-in a session: {ex.Message}");
			}
		}
		#endregion

		#region Validate an OTP session
		static async Task ValidateOTPSessionAsync(HttpContext context, RequestInfo requestInfo)
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
				}).ConfigureAwait(false);

				// register new session
				await InternalAPIs.Cache.RemoveAsync("Session#" + requestInfo.Session.SessionID).ConfigureAwait(false);

				requestInfo.Session.User = json.FromJson<UserIdentity>();
				requestInfo.Session.SessionID = UtilityService.NewUUID;
				await InternalAPIs.CreateSessionAsync(context, requestInfo, true).ConfigureAwait(false);

				// response
				json = new JObject
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "DeviceID", requestInfo.Session.DeviceID }
				};
				requestInfo.Session.UpdateSessionJson(json);

				// response
				await Task.WhenAll(
					context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None),
					InternalAPIs.Cache.RemoveAsync("Attempt#" + requestInfo.Session.IP)
				).ConfigureAwait(false);
				if (Global.IsDebugLogEnabled && Global.IsDebugResultsEnabled)
					await context.WriteLogsAsync("InternalAPIs", $"End process => Response:\r\n{json.ToJson().ToString(Formatting.Indented)}").ConfigureAwait(false);
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
				context.WriteError(ex, requestInfo, $"Error occurred while validating OTP session: {ex.Message}");
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
				await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "DELETE", requestInfo.Query, requestInfo.Header, null, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
				{
					{ "Signature", requestInfo.Header["x-app-token"].GetHMACSHA256(Global.ValidationKey) }
				}, requestInfo.CorrelationID)).ConfigureAwait(false);

				// send update message
				await requestInfo.Session.SendOnlineStatusAsync(false).ConfigureAwait(false);

				// create & register the new session of visitor
				requestInfo.Session.SessionID = UtilityService.NewUUID;
				requestInfo.Session.User = new UserIdentity();
				var session = InternalAPIs.GenerateSessionJson(requestInfo);
				await InternalAPIs.CreateSessionAsync(context, requestInfo).ConfigureAwait(false);

				// response
				var json = new JObject()
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "DeviceID", requestInfo.Session.DeviceID }
				};
				requestInfo.Session.UpdateSessionJson(json);

				await context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None).ConfigureAwait(false);
				if (Global.IsDebugLogEnabled && Global.IsDebugResultsEnabled)
					await context.WriteLogsAsync("InternalAPIs", $"End process => Response:\r\n{json.ToJson().ToString(Formatting.Indented)}").ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				context.WriteError(ex, requestInfo, $"Error occurred while signing-out a session: {ex.Message}");
			}
		}
		#endregion

		#region Activation
		static async Task ActivateAsync(HttpContext context, RequestInfo requestInfo)
		{
			// call service to activate
			var json = await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Activate", "GET", requestInfo.Query, requestInfo.Header, "", requestInfo.Extra, requestInfo.CorrelationID)).ConfigureAwait(false);

			// get user information & register the session
			requestInfo.Session.User = json.FromJson<UserIdentity>();
			var session = InternalAPIs.GenerateSessionJson(requestInfo).ToString(Formatting.None);
			await Task.WhenAll(
				context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "POST")
				{
					Body = session,
					Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "Signature", session.GetHMACSHA256(Global.ValidationKey) }
					},
					CorrelationID = requestInfo.CorrelationID
				}),
				requestInfo.Session.SendOnlineStatusAsync(true)
			).ConfigureAwait(false);

			// response
			json = new JObject()
			{
				{ "ID", requestInfo.Session.SessionID },
				{ "DeviceID", requestInfo.Session.DeviceID }
			};
			requestInfo.Session.UpdateSessionJson(json);

			await context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None).ConfigureAwait(false);
			if (Global.IsDebugLogEnabled && Global.IsDebugResultsEnabled)
				await context.WriteLogsAsync("InternalAPIs", $"End process => Response:\r\n{json.ToJson().ToString(Formatting.Indented)}").ConfigureAwait(false);
		}
		#endregion

		#region JSON Web Token, Session JSON
		internal static byte[] GetEncryptionKey(this Session session) => session.SessionID.GetHMACHash(Global.EncryptionKey, "BLAKE256").GenerateHashKey(256);

		internal static byte[] GetEncryptionIV(this Session session) => session.SessionID.GetHMACHash(Global.EncryptionKey, "BLAKE256").GenerateHashKey(128);

		internal static string GetJSONWebToken(this Session session)
			=> UserIdentity.GetJSONWebToken
			(
				session.User.ID,
				session.SessionID,
				Global.EncryptionKey,
				Global.JWTKey,
				payload => payload["j2f"] = $"{session.Verification.ToString()}|{UtilityService.NewUUID}".Encrypt(Global.EncryptionKey)
			);

		internal static void UpdateSessionJson(this Session session, JObject json)
		{
			json["ID"] = session.SessionID.Encrypt(Global.EncryptionKey.Reverse(), true);
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
						{ "Key", session.GetEncryptionKey().ToHex() },
						{ "IV", session.GetEncryptionIV().ToHex() }
					}
				},
				{
					"JWT",
					Global.JWTKey
				}
			};
			json["JWT"] = session.GetJSONWebToken();
		}

		//internal static async Task SendOnlineStatusAsync(this Session session, bool isOnline)
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

		#region WAMP connections & updaters
		internal static Task OpenChannelsAsync()
			=> Global.OpenChannelsAsync(
				(sender, args) =>
				{
					Global.WriteLogs("InternalAPIs", $"Incomming channel is established - Session ID: {args.SessionId}");
					InternalAPIs.InterCommunicateMessageUpdater = WAMPConnections.IncommingChannel.RealmProxy.Services
						.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages.apigateway")
						.Subscribe(
							async (message) =>
							{
								try
								{
									await InternalAPIs.ProcessInterCommunicateMessageAsync(message).ConfigureAwait(false);
									if (Global.IsDebugLogEnabled)
										await Global.WriteLogsAsync("InternalAPIs", $"Process an inter-communicate message successful\r\n{message?.ToJson().ToString(Formatting.Indented)}").ConfigureAwait(false);
								}
								catch (Exception ex)
								{
									await Global.WriteLogsAsync("InternalAPIs", $"Error occurred while processing an inter-communicate message\r\n{message?.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}", ex).ConfigureAwait(false);
								}
							},
							exception => Global.WriteLogs("InternalAPIs", "Error occurred while fetching inter-communicate message", exception)
						);
				},
				(sender, args) =>
				{
					Global.WriteLogs("InternalAPIs", $"Outgoing channel is established - Session ID: {args.SessionId}");
					try
					{
						Task.WaitAll(new[] { Global.InitializeLoggingServiceAsync(), Global.InitializeRTUServiceAsync() }, 4567);
						Global.WriteLogs("InternalAPIs", "Initializing helper services succesful");
					}
					catch (Exception ex)
					{
						Global.WriteLogs("InternalAPIs", "Error occurred while initializing helper services", ex);
					}
				}
			);

		static ISubject<UpdateMessage> UpdateMessagePublisher = null;
		static IDisposable InterCommunicateMessageUpdater = null;

		internal static async Task SendInterCommunicateMessageAsync(CommunicateMessage message)
		{
			try
			{
				await Global.RTUService.SendInterCommunicateMessageAsync(message, Global.CancellationTokenSource.Token).ConfigureAwait(false);
				await Global.WriteLogsAsync("InternalAPIs", $"Send an inter-communicate message successful\r\n{message.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}").ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await Global.WriteLogsAsync("InternalAPIs", "Error occurred while sending an inter-communicate message", ex).ConfigureAwait(false);
			}
		}

		internal static async Task ProcessInterCommunicateMessageAsync(CommunicateMessage message)
		{
			// update users' sessions with new access token
			if (message.Type.Equals("Session#Update"))
			{
				// prepare
				var sessionID = (message.Data["Session"] as JValue).Value as string;
				var user = (message.Data["User"] as JObject).FromJson<UserIdentity>();
				var deviceID = (message.Data["Device"] as JValue).Value as string;
				var verification = (message.Data["Verification"] as JValue).Value.CastAs<bool>();

				var json = new JObject()
				{
					{ "ID", sessionID },
					{ "UserID", user.ID },
					{ "DeviceID", deviceID }
				};

				// update
				new Session
				{
					SessionID = sessionID,
					DeviceID = deviceID,
					User = user,
					Verification = verification
				}.UpdateSessionJson(json);

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
				var user = (message.Data["User"] as JObject).FromJson<UserIdentity>();
				var deviceID = (message.Data["Device"] as JValue).Value as string;

				var json = new JObject()
				{
					{ "ID", sessionID },
					{ "UserID", user.ID },
					{ "DeviceID", deviceID },
				};

				// update
				new Session
				{
					SessionID = sessionID,
					DeviceID = deviceID,
					User = user
				}.UpdateSessionJson(json);

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
					Global.WriteLogs("InternalAPIs", $"Error occurred while publishing an update message: {message.ToJson().ToString(Formatting.Indented)}", ex);
				}

			else
				try
				{
					InternalAPIs.UpdateMessagePublisher.OnNext(message);
				}
				catch (Exception ex)
				{
					Global.WriteLogs("InternalAPIs", $"Error occurred while publishing an update message: {message.ToJson().ToString(Formatting.Indented)}", ex);
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
					await Global.WriteLogsAsync("InternalAPIs", $"Error occurred while publishing an update message: {message.ToJson().ToString(Formatting.Indented)}", ex).ConfigureAwait(false);
				}

			else
				try
				{
					InternalAPIs.UpdateMessagePublisher.OnNext(message);
				}
				catch (Exception ex)
				{
					await Global.WriteLogsAsync("InternalAPIs", $"Error occurred while publishing an update message: {message.ToJson().ToString(Formatting.Indented)}", ex).ConfigureAwait(false);
				}
		}
		#endregion

	}
}