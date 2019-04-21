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
		internal static ICache Cache { get; set; }
		internal static ILogger Logger { get; set; }
		internal static List<string> ExcludedHeaders { get; } = UtilityService.GetAppSetting("ExcludedHeaders", "connection,accept,accept-encoding,accept-language,cache-control,cookie,content-type,content-length,user-agent,referer,host,origin,if-modified-since,if-none-match,upgrade-insecure-requests,ms-aspnetcore-token,x-forwarded-for,x-forwarded-proto,x-forwarded-port,x-original-for,x-original-proto,x-original-remote-endpoint,x-original-port,cdn-loop,cf-ipcountry,cf-ray,cf-visitor,cf-connecting-ip").ToList();
		internal static HashSet<string> NoTokenRequiredServices { get; } = $"{UtilityService.GetAppSetting("NoTokenRequiredServices", "")}|indexes|discovery".ToLower().ToHashSet('|', true);
		internal static ConcurrentDictionary<string, JObject> Controllers { get; } = new ConcurrentDictionary<string, JObject>();
		internal static ConcurrentDictionary<string, List<JObject>> Services { get; } = new ConcurrentDictionary<string, List<JObject>>();
		#endregion

		internal static async Task ProcessRequestAsync(HttpContext context)
		{
			// prepare the requesting information
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
					isAccountProccessed = requestInfo.Verb.IsEquals("POST");
				}
				else if ("account".IsEquals(requestInfo.ObjectName))
					isAccountProccessed = requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT");
				else if ("activate".IsEquals(requestInfo.ObjectName))
					isActivationProccessed = requestInfo.Verb.IsEquals("GET");
			}

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
				requestInfo.Header.TryAdd("x-app-token", token);
				requestInfo.Header.Remove("authorization");

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
					await context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs.RESTful", "Error occurred while parsing body of the request", ex).ConfigureAwait(false);
				}

			else if (requestInfo.Verb.IsEquals("GET") && requestInfo.Query.ContainsKey("x-body"))
				try
				{
					requestInfo.Body = requestInfo.Query["x-body"].Url64Decode();
				}
				catch (Exception ex)
				{
					await context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs.RESTful", "Error occurred while parsing body of the 'x-body' parameter", ex).ConfigureAwait(false);
				}
			#endregion

			// verify captcha
			try
			{
				requestInfo.CaptchaIsValid(context.Items);
			}
			catch (Exception ex)
			{
				context.WriteError(InternalAPIs.Logger, ex, requestInfo, null, false);
				if (Global.IsDebugLogEnabled)
					Global.Logger.LogError(ex.Message, ex);
				return;
			}

			// prepare related information when working with an account
			if (isAccountProccessed || "otp".IsEquals(requestInfo.ObjectName))
				try
				{
					requestInfo.PrepareAccountRelated(context.Items, async (msg, ex) => await context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs.RESTful", msg, ex));
				}
				catch (Exception ex)
				{
					context.WriteError(InternalAPIs.Logger, ex, requestInfo, null, false);
					if (Global.IsDebugLogEnabled)
						Global.Logger.LogError(ex.Message, ex);
					return;
				}

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

			// process request of discovery (controllers, services, definitions, resources, ...)
			else if (requestInfo.ServiceName.IsEquals("discovery"))
			{
				if (requestInfo.ObjectName.IsEquals("controllers"))
				{
					var response = InternalAPIs.Controllers.Values.Select(controller => new JObject
					{
						{ "ID", controller.Get<string>("ID").GenerateUUID() },
						{ "Platform", controller.Get<string>("Platform") },
						{ "Available" , controller.Get<bool>("Available") }
					}).ToJArray();
					await context.WriteAsync(response, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None, requestInfo.CorrelationID, Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				else if (requestInfo.ObjectName.IsEquals("services"))
				{
					var response = InternalAPIs.Services.Values.Select(svcInfo => new
					{
						URI = $"net.vieapps.services.{svcInfo[0].Get<string>("Name")}",
						Available = svcInfo.FirstOrDefault(svc => svc.Get<bool>("Available") == true) != null,
						Running = svcInfo.FirstOrDefault(svc => svc.Get<bool>("Running") == true) != null
					}).OrderBy(info => info.URI).Select(info => new JObject
					{
						{ "URI", info.URI },
						{ "Available", info.Available },
						{ "Running", info.Running }
					}).ToJArray();
					await context.WriteAsync(response, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None, requestInfo.CorrelationID, Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				else if (requestInfo.ObjectName.IsEquals("definitions"))
					try
					{
						if (!requestInfo.Query.ContainsKey("x-service-name") && !requestInfo.Query.ContainsKey("x-object-name"))
							throw new InvalidRequestException("URI format: /discovery/definitions?x-service-name=<Service Name>&x-object-name=<Object Name>&x-object-identity=<Definition Name>");
						requestInfo.ServiceName = requestInfo.Query["service-name"] = requestInfo.Query["x-service-name"];
						requestInfo.ObjectName = requestInfo.Query["object-name"] = "definitions";
						requestInfo.Query["object-identity"] = requestInfo.Query["x-object-name"];
						requestInfo.Query["mode"] = requestInfo.Query.ContainsKey("x-object-identity") ? requestInfo.Query["x-object-identity"] : "";
						new[] { "x-service-name", "x-object-name", "x-object-identity" }.ForEach(name => requestInfo.Query.Remove(name));
						var response = await context.CallServiceAsync(requestInfo, Global.CancellationTokenSource.Token).ConfigureAwait(false);
						await context.WriteAsync(response, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None, requestInfo.CorrelationID, Global.CancellationTokenSource.Token).ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						context.WriteError(InternalAPIs.Logger, ex, requestInfo);
					}
				else
					context.WriteError(InternalAPIs.Logger, new InvalidRequestException("Unknown request"), requestInfo);
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

			else
			{
				var sessionID = await InternalAPIs.Cache.GetAsync<string>($"Session#{session.SessionID}", Global.CancellationTokenSource.Token).ConfigureAwait(false);
				if (!string.IsNullOrWhiteSpace(sessionID) && sessionID.Equals(session.GetEncryptedID()))
					return true;
				var existed = await context.IsSessionExistAsync(session).ConfigureAwait(false);
				if (existed)
					await session.RefreshAsync().ConfigureAwait(false);
				return existed;
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
						await InternalAPIs.Cache.SetAsync($"Session#{requestInfo.Session.SessionID}", requestInfo.Session.GetEncryptedID(), 13, Global.CancellationTokenSource.Token).ConfigureAwait(false);
					}

					// register session
					else
					{
						// validate
						var registered = await InternalAPIs.Cache.GetAsync<string>($"Session#{requestInfo.Session.SessionID}").ConfigureAwait(false);
						if (!requestInfo.Query["register"].IsEquals(registered))
						{
							var ex = new InvalidSessionException("Session is invalid (The session is not issued by the system)");
							if (Global.IsDebugResultsEnabled)
								Global.Logger.LogError($"{ex.Message} => Registered: {registered} - Requested (encrypted): {requestInfo.Query["register"]}", ex);
							throw ex;
						}

						var requested = requestInfo.Session.GetDecryptedID(requestInfo.Query["register"], Global.EncryptionKey, Global.ValidationKey);
						if (!requestInfo.Session.SessionID.IsEquals(requested))
						{
							var ex = new InvalidSessionException("Session is invalid (The session is not issued by the system)");
							if (Global.IsDebugResultsEnabled)
								Global.Logger.LogError($"{ex.Message} => Current: {requestInfo.Session.SessionID} - Requested (decrypted): {requested}", ex);
							throw ex;
						}

						// register with user service
						await Task.WhenAll(
							context.CreateSessionAsync(requestInfo),
							requestInfo.Session.SendOnlineStatusAsync(true),
							requestInfo.Session.RefreshAsync()
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
						!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs.RESTful", new List<string>
						{
							$"Successfully process request of session (registration of anonymous user)",
							$"- Request: {requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
							$"- Response: {json.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
							$"- Execution times: {context.GetExecutionTimes()}"
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
						requestInfo.Session.SendOnlineStatusAsync(true),
						!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs.RESTful", new List<string>
						{
							$"Successfully process request of session (registration of authenticated user)",
							$"- Request: {requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
							$"- Response: {json.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
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

		#region Create a session
		static async Task CreateSessionAsync(this HttpContext context, RequestInfo requestInfo, bool isOnline = true)
		{
			var body = new JObject
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
				{ "Verification", requestInfo.Session.Verification },
				{ "Online", isOnline }
			}.ToString(Formatting.None);
			await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "POST")
			{
				Body = body,
				Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
				{
					{ "Signature", body.GetHMACSHA256(Global.ValidationKey) }
				},
				CorrelationID = requestInfo.CorrelationID
			}, Global.CancellationTokenSource.Token, InternalAPIs.Logger).ConfigureAwait(false);
		}
		#endregion

		#region Sign a session in
		static async Task SignSessionInAsync(this HttpContext context, RequestInfo requestInfo)
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
					// update status of old session
					oldSessionID = requestInfo.Session.SessionID;
					await requestInfo.Session.SendOnlineStatusAsync(false).ConfigureAwait(false);

					// register new session
					requestInfo.Session.User = json.FromJson<User>();
					requestInfo.Session.User.SessionID = requestInfo.Session.SessionID = UtilityService.NewUUID;
					await Task.WhenAll(
						context.CreateSessionAsync(requestInfo),
						requestInfo.Session.SendOnlineStatusAsync(true)
					).ConfigureAwait(false);

					// prepare response
					json = new JObject
					{
						{ "ID", requestInfo.Session.SessionID },
						{ "DeviceID", requestInfo.Session.DeviceID }
					};
					context.UpdateSessionJson(requestInfo.Session, json as JObject);
				}

				// response
				await Task.WhenAll(
					context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
					requestInfo.Session.RefreshAsync(),
					InternalAPIs.Cache.RemoveAsync("Attempt#" + requestInfo.Session.IP, Global.CancellationTokenSource.Token),
					string.IsNullOrWhiteSpace(oldSessionID) ? Task.CompletedTask : InternalAPIs.Cache.RemoveAsync($"Session#{oldSessionID}", Global.CancellationTokenSource.Token),
					!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs.RESTful", new List<string>
					{
						$"Successfully process request of session (sign-in)",
						$"- Request: {requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"- Response: {json.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"- Execution times: {context.GetExecutionTimes()}"
					})
				).ConfigureAwait(false);

				// broadcast updates
				if (!require2FA)
					await new CommunicateMessage
					{
						ServiceName = "APIGateway",
						Type = "Session#Patch",
						Data = new JObject
						{
							{ "SessionID", oldSessionID },
							{ "SessionXID", json["ID"] },
							{ "Token", json["Token"] }
						}
					}.PublishAsync(RTU.Logger).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				// wait
				var attempt = await InternalAPIs.Cache.ExistsAsync("Attempt#" + requestInfo.Session.IP, Global.CancellationTokenSource.Token).ConfigureAwait(false)
					? await InternalAPIs.Cache.GetAsync<int>("Attempt#" + requestInfo.Session.IP, Global.CancellationTokenSource.Token).ConfigureAwait(false) + 1
					: 1;
				await Task.WhenAll(
					Task.Delay(567 + ((attempt - 1) * 5678)),
					InternalAPIs.Cache.SetAsync("Attempt#" + requestInfo.Session.IP, attempt, 13, Global.CancellationTokenSource.Token)
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
				var json = await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "OTP", "POST")
				{
					Body = new JObject
					{
						{ "ID", id.Encrypt(Global.EncryptionKey) },
						{ "OTP", otp.Encrypt(Global.EncryptionKey) },
						{ "Info", info.Encrypt(Global.EncryptionKey) }
					}.ToString(Formatting.None),
					CorrelationID = requestInfo.CorrelationID
				}, Global.CancellationTokenSource.Token, InternalAPIs.Logger).ConfigureAwait(false);

				// update status of old session
				var oldSessionID = requestInfo.Session.SessionID;
				await requestInfo.Session.SendOnlineStatusAsync(false).ConfigureAwait(false);

				// register new session
				requestInfo.Session.User = json.FromJson<User>();
				requestInfo.Session.User.SessionID = requestInfo.Session.SessionID = UtilityService.NewUUID;
				requestInfo.Session.Verification = true;
				await Task.WhenAll(
					context.CreateSessionAsync(requestInfo),
					requestInfo.Session.SendOnlineStatusAsync(true)
				).ConfigureAwait(false);

				// response
				json = new JObject
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "DeviceID", requestInfo.Session.DeviceID }
				};
				context.UpdateSessionJson(requestInfo.Session, json as JObject);

				await Task.WhenAll(
					context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
					requestInfo.Session.RefreshAsync(),
					InternalAPIs.Cache.RemoveAsync("Attempt#" + requestInfo.Session.IP, Global.CancellationTokenSource.Token),
					InternalAPIs.Cache.RemoveAsync($"Session#{oldSessionID}", Global.CancellationTokenSource.Token),
					!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs.RESTful", new List<string>
					{
						$"Successfully process request of session (OTP validation)",
						$"- Request: {requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"- Response: {json.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"- Execution times: {context.GetExecutionTimes()}"
					})
				).ConfigureAwait(false);

				// broadcast updates
				await new CommunicateMessage
				{
					ServiceName = "APIGateway",
					Type = "Session#Patch",
					Data = new JObject
					{
						{ "SessionID", oldSessionID },
						{ "SessionXID", json["ID"] },
						{ "Token", json["Token"] }
					}
				}.PublishAsync(RTU.Logger).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				// wait
				var attempt = await InternalAPIs.Cache.ExistsAsync("Attempt#" + requestInfo.Session.IP, Global.CancellationTokenSource.Token).ConfigureAwait(false)
					? await InternalAPIs.Cache.GetAsync<int>("Attempt#" + requestInfo.Session.IP, Global.CancellationTokenSource.Token).ConfigureAwait(false) + 1
					: 1;
				await Task.WhenAll(
					Task.Delay(567 + ((attempt - 1) * 5678)),
					InternalAPIs.Cache.SetAsync("Attempt#" + requestInfo.Session.IP, attempt, 13, Global.CancellationTokenSource.Token)
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

				// update status of old session
				var oldSessionID = requestInfo.Session.SessionID;
				await requestInfo.Session.SendOnlineStatusAsync(false).ConfigureAwait(false);

				// create & register the new session of visitor
				requestInfo.Session.SessionID = UtilityService.NewUUID;
				requestInfo.Session.User = new User("", requestInfo.Session.SessionID, new List<string> { SystemRole.All.ToString() }, new List<Privilege>());
				requestInfo.Session.Verification = false;
				await Task.WhenAll(
					context.CreateSessionAsync(requestInfo),
					requestInfo.Session.SendOnlineStatusAsync(true)
				).ConfigureAwait(false);

				// response
				var json = new JObject
				{
					{ "ID", requestInfo.Session.SessionID },
					{ "DeviceID", requestInfo.Session.DeviceID }
				};
				context.UpdateSessionJson(requestInfo.Session, json);

				await Task.WhenAll(
					context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
					requestInfo.Session.RefreshAsync(),
					InternalAPIs.Cache.RemoveAsync($"Session#{oldSessionID}", Global.CancellationTokenSource.Token),
					!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs.RESTful", new List<string>
					{
						$"Successfully process request of session (sign-out)",
						$"- Request: {requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"- Response: {json.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
						$"- Execution times: {context.GetExecutionTimes()}"
					})
				).ConfigureAwait(false);

				// broadcast updates
				await new CommunicateMessage
				{
					ServiceName = "APIGateway",
					Type = "Session#Patch",
					Data = new JObject
					{
						{ "SessionID", oldSessionID },
						{ "SessionXID", json["ID"] },
						{ "Token", json["Token"] }
					}
				}.PublishAsync(RTU.Logger).ConfigureAwait(false);
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
			var json = await context.CallServiceAsync(new RequestInfo(requestInfo)
			{
				ServiceName = "Users",
				ObjectName = "Activate",
				Verb = "GET"
			}, Global.CancellationTokenSource.Token, InternalAPIs.Logger).ConfigureAwait(false);

			// get user information & register the session
			requestInfo.Session.User = json.FromJson<User>();
			requestInfo.Session.User.SessionID = requestInfo.Session.SessionID = UtilityService.NewUUID;
			await Task.WhenAll(
				context.CreateSessionAsync(requestInfo),
				requestInfo.Session.SendOnlineStatusAsync(true)
			).ConfigureAwait(false);

			// response
			json = new JObject
			{
				{ "ID", requestInfo.Session.SessionID },
				{ "DeviceID", requestInfo.Session.DeviceID }
			};
			context.UpdateSessionJson(requestInfo.Session, json as JObject);

			await Task.WhenAll(
				context.WriteAsync(json, Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None, requestInfo.CorrelationID, Global.CancellationTokenSource.Token),
				requestInfo.Session.RefreshAsync(),
				!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(InternalAPIs.Logger, "Http.InternalAPIs.RESTful", new List<string>
				{
					$"Successfully process request of session (activation)",
					$"- Request: {requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
					$"- Response: {json.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}",
					$"- Execution times: {context.GetExecutionTimes()}"
				})
			).ConfigureAwait(false);

			// broadcast updates
			await new CommunicateMessage
			{
				ServiceName = "APIGateway",
				Type = "Session#Patch",
				Data = new JObject
				{
					{ "SessionID", requestInfo.Session.SessionID },
					{ "SessionXID", json["ID"] },
					{ "Token", json["Token"] }
				}
			}.PublishAsync(RTU.Logger).ConfigureAwait(false);
		}
		#endregion

		#region Helper: verify captcha
		internal static void CaptchaIsValid(this RequestInfo requestInfo, IDictionary<object, object> items = null)
		{
			if (!requestInfo.Header.ContainsKey("x-captcha"))
				return;

			requestInfo.Header.TryGetValue("x-captcha-registered", out string registered);
			requestInfo.Header.TryGetValue("x-captcha-input", out string input);
			if (string.IsNullOrWhiteSpace(registered) || string.IsNullOrWhiteSpace(input))
				throw new InvalidRequestException("Captcha code is invalid");

			try
			{
				var key = requestInfo.Session.GetEncryptionKey(Global.EncryptionKey, items);
				var iv = requestInfo.Session.GetEncryptionIV(Global.EncryptionKey, items);
				registered = registered.Decrypt(key, iv);
				input = input.Decrypt(key, iv);
			}
			catch (Exception ex)
			{
				throw new InvalidRequestException("Captcha code is invalid", ex);
			}

			if (!CaptchaService.IsCodeValid(registered, input))
				throw new InvalidRequestException("Captcha code is invalid");
		}
		#endregion

		#region Helper: prepare related information of an account
		internal static void PrepareAccountRelated(this RequestInfo requestInfo, IDictionary<object, object> items = null, Action<string, Exception> onParseError = null)
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
			if (requestInfo.Header.TryGetValue("x-password", out string xPassword) && !string.IsNullOrWhiteSpace(xPassword))
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
			var encryptionKey = requestInfo.Session.GetEncryptionKey(Global.EncryptionKey, items);
			var encryptionIV = requestInfo.Session.GetEncryptionIV(Global.EncryptionKey, items);

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
				if (!requestInfo.Header.ContainsKey("x-captcha"))
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
		}
		#endregion

		#region Heper: keys, session, online status, ...
		internal static string GetEncryptedID(this Session session)
			=> session.GetEncryptedID(session.SessionID, Global.EncryptionKey, Global.ValidationKey);

		internal static void UpdateSessionJson(this Session session, JObject json, IDictionary<object, object> items)
		{
			json["ID"] = session.GetEncryptedID();
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
						{ "Key", session.GetEncryptionKey(Global.EncryptionKey, items).ToHex() },
						{ "IV", session.GetEncryptionIV(Global.EncryptionKey, items).ToHex() }
					}
				},
				{
					"JWT",
					Global.JWTKey
				}
			};
			json["Token"] = session.GetAuthenticateToken();
		}

		internal static void UpdateSessionJson(this HttpContext context, Session session, JObject json)
			=> session.UpdateSessionJson(json, context.Items);

		internal static Task RefreshAsync(this Session session, int time = 0)
			=> InternalAPIs.Cache.SetAsync($"Session#{session.SessionID}", session.GetEncryptedID(), time > 0 ? time : 180, Global.CancellationTokenSource.Token);

		internal static Task SendOnlineStatusAsync(this Session session, bool isOnline)
			=> WAMPConnections.OutgoingChannel != null
				? new CommunicateMessage("Users")
				{
					Type = "Session#Status",
					Data = session.ToJson(json => json["IsOnline"] = isOnline)
				}.PublishAsync(RTU.Logger)
				: Task.CompletedTask;
		#endregion

		#region Helper: WAMP connections
		internal static void OpenWAMPChannels(int waitingTimes = 6789)
		{
			Global.Logger.LogDebug($"Attempting to connect to WAMP router [{new Uri(WAMPConnections.GetRouterStrInfo()).GetResolvedURI()}]");
			Global.OpenWAMPChannels(
				(sender, arguments) =>
				{
					Global.Logger.LogDebug($"Incoming channel to WAMP router is established - Session ID: {arguments.SessionId}");
					WAMPConnections.IncomingChannel.Update(WAMPConnections.IncomingChannelSessionID, Global.ServiceName, $"Incoming ({Global.ServiceName} HTTP service)");
					Global.PrimaryInterCommunicateMessageUpdater?.Dispose();
					Global.PrimaryInterCommunicateMessageUpdater = WAMPConnections.IncomingChannel.RealmProxy.Services
						.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages.apigateway")
						.Subscribe(
							async message =>
							{
								var correlationID = UtilityService.NewUUID;
								try
								{
									await InternalAPIs.ProcessInterCommunicateMessageAsync(message).ConfigureAwait(false);
									if (Global.IsDebugResultsEnabled)
										await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs.RTU",
											$"Successfully process an inter-communicate message" + "\r\n" +
											$"- Type: {message?.Type}" + "\r\n" +
											$"- Message: {message?.Data?.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"
										, null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);
								}
								catch (Exception ex)
								{
									await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs.RTU", $"{ex.Message} => {message?.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}", ex, Global.ServiceName, LogLevel.Error, correlationID).ConfigureAwait(false);
								}
							},
							async exception => await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs.RTU", $"Error occurred while fetching an inter-communicating message => {exception.Message}", exception).ConfigureAwait(false)
						);
				},
				(sender, arguments) =>
				{
					Global.Logger.LogDebug($"Outgoing channel to WAMP router is established - Session ID: {arguments.SessionId}");
					WAMPConnections.OutgoingChannel.Update(WAMPConnections.OutgoingChannelSessionID, Global.ServiceName, $"Outgoing ({Global.ServiceName} HTTP service)");
					Task.Run(async () =>
					{
						try
						{
							await Task.WhenAll(
								Global.InitializeLoggingServiceAsync(),
								Global.InitializeRTUServiceAsync()
							).ConfigureAwait(false);
							Global.Logger.LogInformation("Helper services are succesfully initialized");
							while (WAMPConnections.IncomingChannel == null || WAMPConnections.OutgoingChannel == null)
								await Task.Delay(UtilityService.GetRandomNumber(234, 567), Global.CancellationTokenSource.Token).ConfigureAwait(false);
						}
						catch (Exception ex)
						{
							Global.Logger.LogError($"Error occurred while initializing helper services: {ex.Message}", ex);
						}
					})
					.ContinueWith(async _ => await Global.RegisterServiceAsync().ConfigureAwait(false), TaskContinuationOptions.OnlyOnRanToCompletion)
					.ContinueWith(async _ => await new CommunicateMessage
					{
						ServiceName = "APIGateway",
						Type = "Controller#RequestInfo"
					}.PublishAsync(Global.Logger).ConfigureAwait(false), TaskContinuationOptions.OnlyOnRanToCompletion)
					.ContinueWith(async _ => await new CommunicateMessage
					{
						ServiceName = "APIGateway",
						Type = "Service#RequestInfo"
					}.PublishAsync(Global.Logger).ConfigureAwait(false), TaskContinuationOptions.OnlyOnRanToCompletion)
					.ConfigureAwait(false);
				},
				waitingTimes
			);
		}

		internal static void CloseWAMPChannels(int waitingTimes = 1234)
		{
			Global.UnregisterService();
			Global.PrimaryInterCommunicateMessageUpdater?.Dispose();
			Global.SecondaryInterCommunicateMessageUpdater?.Dispose();
			WAMPConnections.CloseChannels();
		}
		#endregion

		#region Helper: process inter-communicate messages
		internal static async Task ProcessInterCommunicateMessageAsync(CommunicateMessage message)
		{
			// update users' sessions with new access token
			if (message.Type.IsEquals("Session#Update"))
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
			else if (message.Type.IsEquals("Session#Revoke"))
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

			// send information of this service
			else if (message.Type.IsEquals("Service#RequestInfo"))
				await Global.UpdateServiceInfoAsync().ConfigureAwait(false);

			// update information of a service
			else if (message.Type.IsEquals("Service#Info"))
			{
				var name = message.Data.Get<string>("Name");
				if (!InternalAPIs.Services.TryGetValue(name, out List<JObject> services))
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
				if (InternalAPIs.Controllers.TryGetValue(id, out JObject controller))
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
				if (InternalAPIs.Controllers.TryGetValue(id, out JObject controller))
					"User,Host,Platform,Mode,Available,Timestamp".ToArray(',').ForEach(name => controller[name] = message.Data[name]);
				else
					InternalAPIs.Controllers.TryAdd(id, message.Data as JObject);
			}
		}
		#endregion

	}
}