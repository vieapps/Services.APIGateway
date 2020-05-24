#region Related components
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Reactive.Subjects;
using System.Dynamic;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Caching;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class InternalAPIs
	{

		#region Properties
		public static ILogger Logger { get; set; }

		public static List<string> ExcludedHeaders { get; } = UtilityService.GetAppSetting("ExcludedHeaders", "connection,accept,accept-encoding,accept-language,cache-control,cookie,content-type,content-length,user-agent,referer,host,origin,if-modified-since,if-none-match,upgrade-insecure-requests,ms-aspnetcore-token,x-forwarded-for,x-forwarded-proto,x-forwarded-port,x-original-for,x-original-proto,x-original-remote-endpoint,x-original-port,cdn-loop,cf-ipcountry,cf-ray,cf-visitor,cf-connecting-ip,sec-fetch-site,sec-fetch-mode,sec-fetch-dest,sec-fetch-user").ToList();

		public static HashSet<string> NoTokenRequiredServices { get; } = $"{UtilityService.GetAppSetting("NoTokenRequiredServices", "")}|indexes|discovery|webhooks".ToLower().ToHashSet('|', true);

		public static ConcurrentDictionary<string, JObject> Controllers { get; } = new ConcurrentDictionary<string, JObject>();

		public static ConcurrentDictionary<string, List<JObject>> Services { get; } = new ConcurrentDictionary<string, List<JObject>>();

		public static Formatting JsonFormat { get; } = Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None;
		#endregion

		public static async Task ProcessRequestAsync(HttpContext context)
		{
			// prepare the requesting information
			var queryString = context.Request.QueryString.ToDictionary(query =>
			{
				var pathSegments = context.GetRequestPathSegments();
				query["service-name"] = pathSegments.Length > 0 && !string.IsNullOrWhiteSpace(pathSegments[0]) ? pathSegments[0].GetANSIUri(true, true) : "";
				query["object-name"] = pathSegments.Length > 1 && !string.IsNullOrWhiteSpace(pathSegments[1]) ? pathSegments[1].GetANSIUri(true, true) : "";
				query["object-identity"] = pathSegments.Length > 2 && !string.IsNullOrWhiteSpace(pathSegments[2]) ? pathSegments[2].GetANSIUri() : "";
			});
			var extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			if (queryString.Remove("x-request-extra", out var extraInfo) && !string.IsNullOrWhiteSpace(extraInfo))
				try
				{
					extra = extraInfo.Url64Decode().ToExpandoObject().ToDictionary(kvp => kvp.Key, kvp => kvp.Value?.ToString(), StringComparer.OrdinalIgnoreCase);
				}
				catch { }

			var requestInfo = new RequestInfo
			{
				Session = context.GetSession(),
				Verb = context.Request.Method,
				ServiceName = queryString["service-name"].GetCapitalizedFirstLetter(),
				ObjectName = queryString["object-name"].GetCapitalizedFirstLetter(),
				Query = queryString,
				Header = context.Request.Headers.ToDictionary(dictionary => InternalAPIs.ExcludedHeaders.ForEach(name => dictionary.Remove(name))),
				Extra = extra,
				CorrelationID = context.GetCorrelationID()
			};

			#region prepare authenticate token
			bool isSessionProccessed = false, isSessionInitialized = false, isAccountProccessed = false, isActivationProccessed = false;

			if (requestInfo.ServiceName.IsEquals("users"))
			{
				if (requestInfo.ObjectName.IsEquals("session"))
				{
					isSessionProccessed = true;
					isSessionInitialized = requestInfo.Verb.IsEquals("GET");
					isAccountProccessed = requestInfo.Verb.IsEquals("POST");
				}
				else if (requestInfo.ObjectName.IsEquals("account"))
					isAccountProccessed = requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT");
				else if (requestInfo.ObjectName.IsEquals("activate"))
					isActivationProccessed = requestInfo.Verb.IsEquals("GET");
			}

			// authenticate token
			try
			{
				// get token
				var authenticateToken = requestInfo.GetParameter("x-app-token");

				// support for Bearer token
				if (string.IsNullOrWhiteSpace(authenticateToken))
				{
					authenticateToken = context.GetHeaderParameter("authorization");
					authenticateToken = authenticateToken != null && authenticateToken.IsStartsWith("Bearer") ? authenticateToken.ToArray(" ").Last() : null;
					requestInfo.Header["x-app-token"] = authenticateToken;
					requestInfo.Header.Remove("authorization");
				}

				// parse and update information from token
				var tokenIsRequired = isActivationProccessed || (isSessionInitialized && (requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.IsSystemAccount) && !requestInfo.Query.ContainsKey("register"))
					? false
					: !InternalAPIs.NoTokenRequiredServices.Contains(requestInfo.ServiceName);

				if (!string.IsNullOrWhiteSpace(authenticateToken))
				{
					await context.UpdateWithAuthenticateTokenAsync(requestInfo.Session, authenticateToken, 0, null, null, null, InternalAPIs.Logger, "Http.InternalAPIs", requestInfo.CorrelationID).ConfigureAwait(false);
					context.SetSession(requestInfo.Session);
				}
				else if (tokenIsRequired)
					throw new InvalidSessionException("Session is invalid (Token is not found)");

				// check existed of session
				if (tokenIsRequired)
				{
					if (requestInfo.Query.TryGetValue("register", out var registered))
					{
						if (!registered.IsEquals(await Global.Cache.GetAsync<string>($"Session#{requestInfo.Session.SessionID}").ConfigureAwait(false)))
							throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
					}
					else if (!await context.IsSessionExistAsync(requestInfo.Session, InternalAPIs.Logger, "Http.InternalAPIs", requestInfo.CorrelationID).ConfigureAwait(false))
						throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
				}
			}
			catch (Exception ex)
			{
				context.WriteError(InternalAPIs.Logger, ex, requestInfo, null, false);
				if (Global.IsDebugLogEnabled)
					InternalAPIs.Logger.LogError(ex.Message, ex);
				return;
			}
			#endregion

			#region prepare session identity & request body
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
					await context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs", "Error occurred while parsing body of the request", ex).ConfigureAwait(false);
				}

			else if (requestInfo.Verb.IsEquals("GET") && requestInfo.Query.ContainsKey("x-body"))
				try
				{
					requestInfo.Body = requestInfo.Query["x-body"].Url64Decode();
				}
				catch (Exception ex)
				{
					await context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs", "Error occurred while parsing body of the 'x-body' parameter", ex).ConfigureAwait(false);
				}
			#endregion

			// verify captcha
			try
			{
				requestInfo.CaptchaIsValid();
			}
			catch (Exception ex)
			{
				context.WriteError(InternalAPIs.Logger, ex, requestInfo, null, false);
				if (Global.IsDebugLogEnabled)
					InternalAPIs.Logger.LogError(ex.Message, ex);
				return;
			}

			// prepare related information when working with an account
			if (isAccountProccessed || "otp".IsEquals(requestInfo.ObjectName))
				try
				{
					requestInfo.PrepareAccountRelated(async (msg, ex) => await context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs", msg, ex, Global.ServiceName, LogLevel.Error, requestInfo.CorrelationID).ConfigureAwait(false));
				}
				catch (Exception ex)
				{
					context.WriteError(InternalAPIs.Logger, ex, requestInfo, null, false);
					if (Global.IsDebugLogEnabled)
						InternalAPIs.Logger.LogError(ex.Message, ex);
					return;
				}

			// prepare user principal
			context.User = new UserPrincipal(requestInfo.Session.User);

			// process request of sessions
			if (isSessionProccessed)
				switch (requestInfo.Verb)
				{
					case "GET":
						await context.RegisterSessionAsync(requestInfo).ConfigureAwait(false);
						break;

					case "POST":
						await context.LogSessionInAsync(requestInfo).ConfigureAwait(false);
						break;

					case "PUT":
						await context.LogOTPSessionInAsync(requestInfo).ConfigureAwait(false);
						break;

					case "DELETE":
						await context.LogSessionOutAsync(requestInfo).ConfigureAwait(false);
						break;

					default:
						context.WriteError(InternalAPIs.Logger, new MethodNotAllowedException(requestInfo.Verb), requestInfo, null, false);
						break;
				}

			// process request of activations
			else if (isActivationProccessed)
				await context.ActivateAsync(requestInfo).ConfigureAwait(false);

			// process request of discovery (controllers, services, definitions, resources, ...)
			else if (requestInfo.ServiceName.IsEquals("discovery"))
				try
				{
					var response = requestInfo.ObjectName.IsEquals("controllers")
						? InternalAPIs.GetControllers()
						: requestInfo.ObjectName.IsEquals("services")
							? InternalAPIs.GetServices()
							: requestInfo.ObjectName.IsEquals("definitions")
								? await context.CallServiceAsync(requestInfo.PrepareDefinitionRelated(), Global.CancellationTokenSource.Token, InternalAPIs.Logger, "Http.InternalAPIs").ConfigureAwait(false)
								: throw new InvalidRequestException("Unknown request");
					await context.WriteAsync(response, InternalAPIs.JsonFormat, requestInfo.CorrelationID, Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(InternalAPIs.Logger, ex, requestInfo);
				}

			// process request of services
			else
				try
				{
					// prepare signature when work with accounts
					if (isAccountProccessed)
					{
						if (requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT"))
							requestInfo.Extra["Signature"] = requestInfo.Body.GetHMACSHA256(Global.ValidationKey);
						else if (requestInfo.Header.TryGetValue("x-app-token", out var authenticateToken))
							requestInfo.Extra["Signature"] = authenticateToken.GetHMACSHA256(Global.ValidationKey);
					}

					// prepare signature when work with files
					else if (requestInfo.ServiceName.IsEquals("files"))
					{
						if (requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT"))
							requestInfo.Extra["Signature"] = requestInfo.Body.GetHMACSHA256(Global.ValidationKey);
						else if (requestInfo.Header.TryGetValue("x-app-token", out var authenticateToken))
							requestInfo.Extra["Signature"] = authenticateToken.GetHMACSHA256(Global.ValidationKey);
						requestInfo.Extra["SessionID"] = requestInfo.Session.SessionID.GetHMACBLAKE256(Global.ValidationKey);
					}

					// call the service
					var response = await context.CallServiceAsync(requestInfo, Global.CancellationTokenSource.Token, InternalAPIs.Logger, "Http.InternalAPIs").ConfigureAwait(false);
					await context.WriteAsync(response, InternalAPIs.JsonFormat, requestInfo.CorrelationID, Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(InternalAPIs.Logger, ex, requestInfo);
				}
		}

		#region Send state message of a session
		public static async Task SendSessionStateAsync(this Session session, bool isOnline, string correlationID = null)
		{
			if (!string.IsNullOrWhiteSpace(session.User.ID))
				await new UpdateMessage
				{
					Type = "Users#Session#State",
					DeviceID = "*",
					Data = new JObject
					{
						{ "SessionID", session.GetEncryptedID(session.SessionID) },
						{ "UserID", session.User.ID },
						{ "DeviceID", session.DeviceID },
						{ "AppName", session.AppName },
						{ "AppPlatform", session.AppPlatform },
						{ "Location", await session.GetLocationAsync(correlationID, Global.CancellationTokenSource.Token).ConfigureAwait(false) },
						{ "IsOnline", isOnline }
					}
				}.PublishAsync(RTU.Logger, "Http.InternalAPIs").ConfigureAwait(false);
		}
		#endregion

		#region Create/Renew a session
		static async Task CreateOrRenewSessionAsync(this HttpContext context, RequestInfo requestInfo, JToken session = null, bool sendSessionState = true)
		{
			// call the service of users to create/renew session
			session = session ?? new JObject
			{
				{ "ID", requestInfo.Session.SessionID },
				{ "IssuedAt", DateTime.Now },
				{ "RenewedAt", DateTime.Now },
				{ "ExpiredAt", DateTime.Now.AddDays(90) },
				{ "UserID", requestInfo.Session.User.ID },
				{ "AccessToken", requestInfo.Session.User.GetAccessToken(Global.ECCKey) },
				{ "IP", requestInfo.Session.IP },
				{ "DeviceID", requestInfo.Session.DeviceID },
				{ "DeveloperID", requestInfo.Session.DeveloperID },
				{ "AppID", requestInfo.Session.AppID },
				{ "AppInfo", requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform },
				{ "OSInfo", $"{requestInfo.Session.AppAgent.GetOSInfo()} [{requestInfo.Session.AppAgent}]" },
				{ "Verified", requestInfo.Session.Verified },
				{ "Online", true }
			};
			var body = session.ToString(Formatting.None);
			await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "POST")
			{
				Body = body,
				Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
				{
					{ "Signature", body.GetHMACSHA256(Global.ValidationKey) }
				},
				CorrelationID = requestInfo.CorrelationID
			}, Global.CancellationTokenSource.Token, InternalAPIs.Logger, "Http.InternalAPIs").ConfigureAwait(false);

			// update session state
			if (sendSessionState)
				await Task.WhenAll(
					requestInfo.Session.SendSessionStateAsync(true, requestInfo.CorrelationID),
					new CommunicateMessage("Users")
					{
						Type = "Session#State",
						Data = new JObject
						{
							{ "SessionID", requestInfo.Session.SessionID },
							{ "UserID", requestInfo.Session.User.ID },
							{ "IsOnline", true }
						}
					}.PublishAsync(InternalAPIs.Logger, "Http.InternalAPIs")
				).ConfigureAwait(false);
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
						await Global.Cache.SetAsync($"Session#{requestInfo.Session.SessionID}", requestInfo.Session.GetEncryptedID(), 13, Global.CancellationTokenSource.Token).ConfigureAwait(false);
					}

					// register session
					else
					{
						// validate
						var registered = await Global.Cache.GetAsync<string>($"Session#{requestInfo.Session.SessionID}").ConfigureAwait(false);
						if (!requestInfo.Query["register"].IsEquals(registered))
						{
							var ex = new InvalidSessionException("Session is invalid (The session is not issued by the system)");
							if (Global.IsDebugResultsEnabled)
								await context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs", $"{ex.Message} => Registered: {registered} - Requested (encrypted): {requestInfo.Query["register"]}", ex);
							throw ex;
						}

						var requested = requestInfo.Session.GetDecryptedID(requestInfo.Query["register"], Global.EncryptionKey, Global.ValidationKey);
						if (!requestInfo.Session.SessionID.IsEquals(requested))
						{
							var ex = new InvalidSessionException("Session is invalid (The session is not issued by the system)");
							if (Global.IsDebugResultsEnabled)
								await context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs", $"{ex.Message} => Current: {requestInfo.Session.SessionID} - Requested (decrypted): {requested}", ex);
							throw ex;
						}

						// register the new session
						await Task.WhenAll(
							context.CreateOrRenewSessionAsync(requestInfo),
							Global.Cache.RemoveAsync($"Session#{requestInfo.Session.SessionID}", Global.CancellationTokenSource.Token)
						).ConfigureAwait(false);
					}

					// response
					var response = requestInfo.Session.GetSessionJson();
					await Task.WhenAll(
						context.WriteAsync(response, InternalAPIs.JsonFormat, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
						!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs", new List<string>
						{
							$"Successfully process request of session (registration of anonymous user)",
							$"- Request: {requestInfo.ToJson().ToString(InternalAPIs.JsonFormat)}",
							$"- Response: {response.ToJson().ToString(InternalAPIs.JsonFormat)}",
							$"- Execution times: {context.GetExecutionTimes()}"
						})
					).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(InternalAPIs.Logger, ex, requestInfo, null, false);
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
					}, Global.CancellationTokenSource.Token, InternalAPIs.Logger, "Http.InternalAPIs").ConfigureAwait(false);

					// check
					if (session == null)
						throw new SessionNotFoundException();
					else if (!requestInfo.Session.User.ID.IsEquals(session.Get<string>("UserID")))
						throw new InvalidTokenException();

					// update session
					session["RenewedAt"] = DateTime.Now;
					session["ExpiredAt"] = DateTime.Now.AddDays(90);
					session["IP"] = requestInfo.Session.IP;
					session["DeviceID"] = requestInfo.Session.DeviceID;
					session["DeveloperID"] = requestInfo.Session.DeveloperID;
					session["AppID"] = requestInfo.Session.AppID;
					session["AppInfo"] = requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform;
					session["OSInfo"] = $"{requestInfo.Session.AppAgent.GetOSInfo()} [{requestInfo.Session.AppAgent}]";
					session["Online"] = true;
					await context.CreateOrRenewSessionAsync(requestInfo, session).ConfigureAwait(false);

					// response
					var response = requestInfo.Session.GetSessionJson();
					await Task.WhenAll(
						context.WriteAsync(response, InternalAPIs.JsonFormat, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
						!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs", new List<string>
						{
							$"Successfully process request of session (registration of authenticated user)",
							$"- Request: {requestInfo.ToJson().ToString(InternalAPIs.JsonFormat)}",
							$"- Response: {response.ToJson().ToString(InternalAPIs.JsonFormat)}",
							$"- Execution times: {context.GetExecutionTimes()}"
						})
					).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(InternalAPIs.Logger, ex, requestInfo);
				}
		}
		#endregion

		#region Log a session in
		static async Task LogSessionInAsync(this HttpContext context, RequestInfo requestInfo)
		{
			try
			{
				// check
				if (!requestInfo.Extra.ContainsKey("Email") || !requestInfo.Extra.ContainsKey("Password"))
					throw new InvalidDataException("Request JSON is invalid (email/password must be encrypted by RSA before sending)");

				// call service to perform sign in
				var body = new JObject
				{
					{ "Type", requestInfo.GetBodyExpando().Get("Type", "BuiltIn") },
					{ "Email", requestInfo.Extra["Email"] },
					{ "Password", requestInfo.Extra["Password"] },
				}.ToString(Formatting.None);

				var response = await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "PUT")
				{
					Body = body,
					Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "Signature", body.GetHMACSHA256(Global.ValidationKey) }
					},
					CorrelationID = requestInfo.CorrelationID
				}, Global.CancellationTokenSource.Token, InternalAPIs.Logger, "Http.InternalAPIs").ConfigureAwait(false);

				// two-factors authentication
				var oldSessionID = string.Empty;
				var oldUserID = string.Empty;
				var require2FA = response["Require2FA"] != null
					? response.Get<bool>("Require2FA")
					: false;

				if (require2FA)
					response = new JObject
					{
						{ "ID", response.Get<string>("ID") },
						{ "Require2FA", true },
						{ "Providers", response["Providers"] as JArray }
					};

				else
				{
					// update status of old session
					await requestInfo.Session.SendSessionStateAsync(false, requestInfo.CorrelationID).ConfigureAwait(false);

					// register new session
					oldSessionID = requestInfo.Session.SessionID;
					oldUserID = requestInfo.Session.User.ID;
					requestInfo.Session.User = response.Copy<User>();
					requestInfo.Session.User.SessionID = requestInfo.Session.SessionID = UtilityService.NewUUID;
					await context.CreateOrRenewSessionAsync(requestInfo).ConfigureAwait(false);

					// prepare response
					response = requestInfo.Session.GetSessionJson();

					// broadcast updates
					await new CommunicateMessage("APIGateway")
					{
						Type = "Session#Patch",
						Data = new JObject
						{
							{ "SessionID", oldSessionID },
							{ "EncryptedID", response["ID"] },
							{ "AuthenticateToken", response["Token"] }
						}
					}.PublishAsync(RTU.Logger, "Http.InternalAPIs").ConfigureAwait(false);
				}

				// response
				await Task.WhenAll(
					context.WriteAsync(response, InternalAPIs.JsonFormat, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
					Global.Cache.RemoveAsync("Attempt#" + requestInfo.Session.IP, Global.CancellationTokenSource.Token),
					!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs", new List<string>
					{
						$"Successfully process request of session (sign-in)",
						$"- Request: {requestInfo.ToJson().ToString(InternalAPIs.JsonFormat)}",
						$"- Response: {response.ToJson().ToString(InternalAPIs.JsonFormat)}",
						$"- Execution times: {context.GetExecutionTimes()}"
					})
				).ConfigureAwait(false);

				// update state of old session
				if (!string.IsNullOrWhiteSpace(oldSessionID))
					await new CommunicateMessage("Users")
					{
						Type = "Session#State",
						Data = new JObject
						{
							{ "SessionID", oldSessionID },
							{ "UserID", oldUserID },
							{ "IsOnline", false }
						}
					}.PublishAsync(InternalAPIs.Logger, "Http.InternalAPIs").ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				// wait
				var attempt = await Global.Cache.ExistsAsync("APIs:Attempt#" + requestInfo.Session.IP, Global.CancellationTokenSource.Token).ConfigureAwait(false)
					? await Global.Cache.GetAsync<int>("APIs:Attempt#" + requestInfo.Session.IP, Global.CancellationTokenSource.Token).ConfigureAwait(false) + 1
					: 1;
				await Task.WhenAll(
					Task.Delay(567 + ((attempt - 1) * 5678)),
					Global.Cache.SetAsync("APIs:Attempt#" + requestInfo.Session.IP, attempt, 13, Global.CancellationTokenSource.Token)
				).ConfigureAwait(false);

				// show error
				context.WriteError(InternalAPIs.Logger, ex, requestInfo);
			}
		}
		#endregion

		#region Log an OTP session in
		static async Task LogOTPSessionInAsync(this HttpContext context, RequestInfo requestInfo)
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
				var response = await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "OTP", "POST")
				{
					Body = new JObject
					{
						{ "ID", id.Encrypt(Global.EncryptionKey) },
						{ "OTP", otp.Encrypt(Global.EncryptionKey) },
						{ "Info", info.Encrypt(Global.EncryptionKey) }
					}.ToString(Formatting.None),
					CorrelationID = requestInfo.CorrelationID
				}, Global.CancellationTokenSource.Token, InternalAPIs.Logger, "Http.InternalAPIs").ConfigureAwait(false);

				// update status of old session
				await requestInfo.Session.SendSessionStateAsync(false, requestInfo.CorrelationID).ConfigureAwait(false);

				// register new session
				var oldSessionID = requestInfo.Session.SessionID;
				var oldUserID = requestInfo.Session.User.ID;
				requestInfo.Session.User = response.Copy<User>();
				requestInfo.Session.User.SessionID = requestInfo.Session.SessionID = UtilityService.NewUUID;
				requestInfo.Session.Verified = true;
				await context.CreateOrRenewSessionAsync(requestInfo).ConfigureAwait(false);

				// prepare response
				response = requestInfo.Session.GetSessionJson();

				// broadcast updates
				await new CommunicateMessage("APIGateway")
				{
					Type = "Session#Patch",
					Data = new JObject
					{
						{ "SessionID", oldSessionID },
						{ "EncryptedID", response["ID"] },
						{ "AuthenticateToken", response["Token"] }
					}
				}.PublishAsync(RTU.Logger, "Http.InternalAPIs").ConfigureAwait(false);

				// response
				await Task.WhenAll(
					context.WriteAsync(response, InternalAPIs.JsonFormat, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
					Global.Cache.RemoveAsync("APIs:Attempt#" + requestInfo.Session.IP, Global.CancellationTokenSource.Token),
					Global.IsDebugResultsEnabled ? context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs", new List<string>
					{
						$"Successfully process request of session (OTP validation)",
						$"- Request: {requestInfo.ToJson().ToString(InternalAPIs.JsonFormat)}",
						$"- Response: {response.ToJson().ToString(InternalAPIs.JsonFormat)}",
						$"- Execution times: {context.GetExecutionTimes()}"
					}) : Task.CompletedTask
				).ConfigureAwait(false);

				// update state of old session
				await new CommunicateMessage("Users")
				{
					Type = "Session#State",
					Data = new JObject
					{
						{ "SessionID", oldSessionID },
						{ "UserID", oldUserID },
						{ "IsOnline", false }
					}
				}.PublishAsync(InternalAPIs.Logger, "Http.InternalAPIs").ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				// wait
				var attempt = await Global.Cache.ExistsAsync("APIs:Attempt#" + requestInfo.Session.IP, Global.CancellationTokenSource.Token).ConfigureAwait(false)
					? await Global.Cache.GetAsync<int>("APIs:Attempt#" + requestInfo.Session.IP, Global.CancellationTokenSource.Token).ConfigureAwait(false) + 1
					: 1;
				await Task.WhenAll(
					Task.Delay(567 + ((attempt - 1) * 5678)),
					Global.Cache.SetAsync("APIs:Attempt#" + requestInfo.Session.IP, attempt, 13, Global.CancellationTokenSource.Token)
				).ConfigureAwait(false);

				// show error
				context.WriteError(InternalAPIs.Logger, ex, requestInfo);
			}
		}
		#endregion

		#region Log a session out
		static async Task LogSessionOutAsync(this HttpContext context, RequestInfo requestInfo)
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
						["Signature"] = requestInfo.Header["x-app-token"].GetHMACSHA256(Global.ValidationKey)
					},
					CorrelationID = requestInfo.CorrelationID
				}, Global.CancellationTokenSource.Token, InternalAPIs.Logger, "Http.InternalAPIs").ConfigureAwait(false);

				// update status of old session
				await requestInfo.Session.SendSessionStateAsync(false, requestInfo.CorrelationID).ConfigureAwait(false);

				// prepare new session
				var oldSessionID = requestInfo.Session.SessionID;
				var oldUserID = requestInfo.Session.User.ID;
				requestInfo.Session.SessionID = UtilityService.NewUUID;
				requestInfo.Session.User = new User("", requestInfo.Session.SessionID, new List<string> { SystemRole.All.ToString() }, new List<Privilege>());
				requestInfo.Session.Verified = false;
				await Task.WhenAll(
					context.CreateOrRenewSessionAsync(requestInfo, null, false),
					Global.Cache.SetAsync($"Session#{requestInfo.Session.SessionID}", requestInfo.Session.GetEncryptedID(), 13, Global.CancellationTokenSource.Token)
				).ConfigureAwait(false);

				// prepare response
				var response = requestInfo.Session.GetSessionJson();

				// broadcast updates
				await new CommunicateMessage("APIGateway")
				{
					Type = "Session#Patch",
					Data = new JObject
					{
						{ "SessionID", oldSessionID },
						{ "EncryptedID", response["ID"] },
						{ "AuthenticateToken", response["Token"] }
					}
				}.PublishAsync(RTU.Logger, "Http.InternalAPIs").ConfigureAwait(false);

				// response
				await Task.WhenAll(
					context.WriteAsync(response, InternalAPIs.JsonFormat, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
					!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs", new List<string>
					{
						$"Successfully process request of session (sign-out)",
						$"- Request: {requestInfo.ToJson().ToString(InternalAPIs.JsonFormat)}",
						$"- Response: {response.ToJson().ToString(InternalAPIs.JsonFormat)}",
						$"- Execution times: {context.GetExecutionTimes()}"
					})
				).ConfigureAwait(false);

				// update state of old session
				await new CommunicateMessage("Users")
				{
					Type = "Session#State",
					Data = new JObject
					{
						{ "SessionID", oldSessionID },
						{ "UserID", oldUserID },
						{ "IsOnline", false }
					}
				}.PublishAsync(InternalAPIs.Logger, "Http.InternalAPIs").ConfigureAwait(false);
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
			try
			{
				// prepare device identity
				if (string.IsNullOrWhiteSpace(requestInfo.Session.DeviceID))
					requestInfo.Session.DeviceID = (requestInfo.Session.AppName + "/" + requestInfo.Session.AppPlatform + "@" + (requestInfo.Session.AppAgent ?? "N/A")).GetHMACSHA384(requestInfo.Session.SessionID, true) + "@pwa";

				// call service to activate
				var response = await context.CallServiceAsync(new RequestInfo(requestInfo)
				{
					ServiceName = "Users",
					ObjectName = "Activate",
					Verb = "GET"
				}, Global.CancellationTokenSource.Token, InternalAPIs.Logger, "Http.InternalAPIs").ConfigureAwait(false);

				// get user information & register the session
				requestInfo.Session.User = response.Copy<User>();
				requestInfo.Session.User.SessionID = requestInfo.Session.SessionID = UtilityService.NewUUID;
				await context.CreateOrRenewSessionAsync(requestInfo).ConfigureAwait(false);

				// response
				response = requestInfo.Session.GetSessionJson();
				await Task.WhenAll(
					context.WriteAsync(response, InternalAPIs.JsonFormat, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
					!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs", new List<string>
					{
						$"Successfully process request of session (activation)",
						$"- Request: {requestInfo.ToJson().ToString(InternalAPIs.JsonFormat)}",
						$"- Response: {response.ToJson().ToString(InternalAPIs.JsonFormat)}",
						$"- Execution times: {context.GetExecutionTimes()}"
					})
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				context.WriteError(InternalAPIs.Logger, ex, requestInfo);
			}
		}
		#endregion

		#region Helper: verify captcha, prepare related information of an account or request of a definition
		public static RequestInfo CaptchaIsValid(this RequestInfo requestInfo)
		{
			if (!requestInfo.Header.ContainsKey("x-captcha"))
				return requestInfo;

			requestInfo.Header.TryGetValue("x-captcha-registered", out var registered);
			requestInfo.Header.TryGetValue("x-captcha-input", out var input);
			if (string.IsNullOrWhiteSpace(registered) || string.IsNullOrWhiteSpace(input))
				throw new InvalidRequestException("Captcha code is invalid");

			try
			{
				var encryptionKey = requestInfo.Session.GetEncryptionKey(Global.EncryptionKey);
				var encryptionIV = requestInfo.Session.GetEncryptionIV(Global.EncryptionKey);
				registered = registered.Decrypt(encryptionKey, encryptionIV);
				input = input.Decrypt(encryptionKey, encryptionIV);
			}
			catch (Exception ex)
			{
				throw new InvalidRequestException("Captcha code is invalid", ex);
			}

			if (!CaptchaService.IsCodeValid(registered, input))
				throw new InvalidRequestException("Captcha code is invalid");

			return requestInfo;
		}

		public static RequestInfo PrepareAccountRelated(this RequestInfo requestInfo, Action<string, Exception> onParseError = null)
		{
			// prepare body
			var requestBody = requestInfo.GetBodyExpando();
			if (requestBody == null)
				throw new InvalidRequestException("Request is invalid (empty)");

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
					throw new InvalidRequestException("Request is invalid (email must be encrypted by RSA before sending)", ex);
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
					throw new InvalidRequestException("Request is invalid (password must be encrypted by RSA before sending)", ex);
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
					throw new InvalidRequestException("Request is invalid (password must be encrypted by RSA before sending)", ex);
				}

			// prepare x-password
			if (requestInfo.Header.TryGetValue("x-password", out var xPassword) && !string.IsNullOrWhiteSpace(xPassword))
				try
				{
					xPassword = Global.RSA.Decrypt(xPassword);
					requestInfo.Extra["x-password"] = xPassword.Encrypt(Global.EncryptionKey);
				}
				catch (Exception ex)
				{
					throw new InvalidRequestException("Request is invalid (x-password must be encrypted by RSA before sending)", ex);
				}

			// key & iv
			var encryptionKey = requestInfo.Session.GetEncryptionKey(Global.EncryptionKey);
			var encryptionIV = requestInfo.Session.GetEncryptionIV(Global.EncryptionKey);

			// prepare roles
			var roles = requestBody.Get<string>("Roles");
			if (!string.IsNullOrWhiteSpace(roles))
				try
				{
					roles = roles.Decrypt(encryptionKey, encryptionIV);
					requestInfo.Extra["Roles"] = roles.Encrypt(Global.EncryptionKey);
				}
				catch (Exception ex)
				{
					onParseError?.Invoke($"Error occurred while parsing roles => {ex.Message}", ex);
				}

			// prepare privileges
			var privileges = requestBody.Get<string>("Privileges");
			if (!string.IsNullOrWhiteSpace(privileges))
				try
				{
					privileges = privileges.Decrypt(encryptionKey, encryptionIV);
					requestInfo.Extra["Privileges"] = privileges.Encrypt(Global.EncryptionKey);
				}
				catch (Exception ex)
				{
					onParseError?.Invoke($"Error occurred while parsing privileges => {ex.Message}", ex);
				}

			// prepare information of related service
			var relatedInfo = requestInfo.Query.ContainsKey("related-service")
				? requestBody.Get<string>("RelatedInfo")
				: null;
			if (!string.IsNullOrWhiteSpace(relatedInfo))
				try
				{
					relatedInfo = relatedInfo.Decrypt(encryptionKey, encryptionIV);
					requestInfo.Extra["RelatedInfo"] = relatedInfo.Encrypt(Global.EncryptionKey);
				}
				catch (Exception ex)
				{
					onParseError?.Invoke($"Error occurred while parsing information of related service => {ex.Message}", ex);
				}

			// preapare
			var objectIdentity = requestInfo.GetObjectIdentity();

			// prepare to register/create new account
			if (string.IsNullOrWhiteSpace(objectIdentity))
			{
				if (requestInfo.ServiceName.IsEquals("users") && requestInfo.ObjectName.IsEquals("account") && !requestInfo.Header.ContainsKey("x-captcha"))
					throw new InvalidRequestException("Captcha code is invalid");
				var requestCreateAccount = requestInfo.GetHeaderParameter("x-create");
				if (!string.IsNullOrWhiteSpace(requestCreateAccount) && requestCreateAccount.Equals(requestInfo.Session.GetEncryptedID()))
					requestInfo.Extra["x-create"] = "";
			}

			// prepare to invite
			else if ("invite".IsEquals(objectIdentity))
				requestInfo.Extra["x-invite"] = "";

			// prepare to reset password
			else if ("reset".IsEquals(objectIdentity))
			{
				if (!requestInfo.Header.ContainsKey("x-captcha"))
					throw new InvalidRequestException("Captcha code is invalid");
				if (string.IsNullOrWhiteSpace(email))
					throw new InvalidRequestException("Request is invalid (email is null or empty)");
			}

			// prepare to update password
			else if ("password".IsEquals(objectIdentity) && (string.IsNullOrWhiteSpace(oldPassword) || string.IsNullOrWhiteSpace(password)))
				throw new InvalidRequestException("Request is invalid (password is null or empty)");

			// prepare to update email
			else if ("email".IsEquals(objectIdentity) && (string.IsNullOrWhiteSpace(oldPassword) || string.IsNullOrWhiteSpace(email)))
				throw new InvalidRequestException("Request is invalid (password/email is null or empty)");

			return requestInfo;
		}

		public static RequestInfo PrepareDefinitionRelated(this RequestInfo requestInfo)
		{
			if (!requestInfo.Query.ContainsKey("x-service-name") || !requestInfo.Query.ContainsKey("x-object-name"))
				throw new InvalidRequestException("URI format: /discovery/definitions?x-service-name=<Service Name>&x-object-name=<Object Name>&x-object-identity=<Definition Name>");

			requestInfo.ServiceName = requestInfo.Query["service-name"] = requestInfo.Query["x-service-name"];
			requestInfo.ObjectName = requestInfo.Query["object-name"] = "definitions";
			requestInfo.Query["object-identity"] = requestInfo.Query["x-object-name"];
			requestInfo.Query["mode"] = requestInfo.Query.TryGetValue("x-object-identity", out var mode) ? mode : "";

			new[] { "x-service-name", "x-object-name", "x-object-identity" }.ForEach(name => requestInfo.Query.Remove(name));
			return requestInfo;
		}
		#endregion

		#region Heper: keys & sessions
		public static string GetEncryptedID(this Session session)
			=> session.GetEncryptedID(session.SessionID, Global.EncryptionKey, Global.ValidationKey);

		public static JObject GetSessionJson(this Session session)
		{
			var encryptionKey = session.GetEncryptionKey(Global.EncryptionKey);
			var encryptionIV = session.GetEncryptionIV(Global.EncryptionKey);
			return new JObject
			{
				{ "ID", session.GetEncryptedID() },
				{ "DeviceID", session.DeviceID },
				{ "Token", session.GetAuthenticateToken() },
				{  "Keys", new JObject
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
								{ "Key", encryptionKey.ToHex() },
								{ "IV", encryptionIV.ToHex() }
							}
						},
						{
							"JWT",
							Global.JWTKey.Encrypt(encryptionKey, encryptionIV)
						}
					}
				}
			};
		}
		#endregion

		#region Helper: controllers & services
		public static JToken GetControllers()
			=> InternalAPIs.Controllers.Values.Select(info => new JObject
			{
				{ "ID", info.Get<string>("ID").GenerateUUID() },
				{ "Platform", info.Get<string>("Platform") },
				{ "Available" , info.Get<bool>("Available") }
			})
			.ToJArray();

		public static JToken GetServices()
			=> InternalAPIs.Services.Values.Select(info => new
			{
				URI = $"services.{info[0].Get<string>("Name")}",
				Available = info.FirstOrDefault(svc => svc.Get<bool>("Available")) != null,
				Running = info.FirstOrDefault(svc => svc.Get<bool>("Running")) != null
			})
			.OrderBy(info => info.URI)
			.Select(info => new JObject
			{
				{ "URI", info.URI },
				{ "Available", info.Available },
				{ "Running", info.Running }
			})
			.ToJArray();
		#endregion

		#region Helper: process inter-communicate messages
		public static async Task ProcessInterCommunicateMessageAsync(CommunicateMessage message)
		{
			// send information of this service
			if (message.Type.IsEquals("Service#RequestInfo"))
				await Global.SendServiceInfoAsync("Http.InternalAPIs").ConfigureAwait(false);

			// update information of a service
			else if (message.Type.IsEquals("Service#Info"))
			{
				var name = message.Data.Get<string>("Name");
				if (!InternalAPIs.Services.TryGetValue(name, out var services))
					InternalAPIs.Services.TryAdd(name, new List<JObject> { message.Data as JObject });
				else
				{
					var controllerID = message.Data.Get<string>("ControllerID");
					var service = services.FirstOrDefault(svc => name.IsEquals(svc.Get<string>("Name")) && controllerID.IsEquals(svc.Get<string>("ControllerID")));
					if (service == null)
						services.Add(message.Data as JObject);
					else
					{
						service["InvokeInfo"] = message.Data["InvokeInfo"];
						service["Available"] = message.Data["Available"];
						service["Running"] = message.Data["Running"];
					}
				}
			}

			// update information of a controller
			else if (message.Type.IsEquals("Controller#Disconnect"))
			{
				var id = message.Data.Get<string>("ID");
				if (InternalAPIs.Controllers.TryGetValue(id, out var controller))
				{
					controller["Available"] = false;
					var controllerID = controller.Get<string>("ID");
					InternalAPIs.Services.ForEach(kvp =>
					{
						var service = kvp.Value.FirstOrDefault(svc => kvp.Key.IsEquals(svc.Get<string>("Name")) && controllerID.IsEquals(svc.Get<string>("ControllerID")));
						if (service != null)
							service["Available"] = service["Running"] = false;
					});
				}
			}
			else if (message.Type.IsEquals("Controller#Info") || message.Type.IsEquals("Controller#Connect"))
			{
				var id = message.Data.Get<string>("ID");
				if (InternalAPIs.Controllers.TryGetValue(id, out var controller))
					new[] { "User", "Host", "Platform", "Mode", "Available", "Timestamp" }.ForEach(name => controller[name] = message.Data[name]);
				else
					InternalAPIs.Controllers.TryAdd(id, message.Data as JObject);
			}
		}
		#endregion

	}
}