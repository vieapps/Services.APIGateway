#region Related components
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Caching;
using net.vieapps.Components.Repository;
using net.vieapps.Components.Security;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class RESTfulAPIs
	{

		#region Properties
		public static ILogger Logger { get; set; }

		public static ConcurrentDictionary<string, (Type Type, string EndpointURL, string DataSource)> ServiceForwarders { get; } = [];

		public static ConcurrentDictionary<string, JObject> Controllers { get; } = [];

		public static ConcurrentDictionary<string, List<JObject>> Services { get; } = [];

		public static List<string> ExcludedHeaders { get; } = UtilityService.GetAppSetting("APIs:ExcludedHeaders", "connection,accept,accept-encoding,accept-language,cache-control,cookie,content-type,content-length,user-agent,referer,host,origin,if-modified-since,if-none-match,upgrade-insecure-requests,priority,purpose,ms-aspnetcore-token,x-forwarded-for,x-forwarded-proto,x-forwarded-port,x-original-for,x-original-proto,x-original-remote-endpoint,x-original-port,cdn-loop").ToList();

		public static HashSet<string> NoTokenRequiredServices { get; } = $"{UtilityService.GetAppSetting("APIs:NoTokenRequiredServices", "")}|indexes|iplocations|discovery|webhook|webhooks".ToLower().ToHashSet('|', true);

		public static string PrivateToken { get; } = UtilityService.GetAppSetting("APIs:PrivateToken", UtilityService.NewUUID);

		public static Formatting JsonFormat { get; } = Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None;

		public static int ExpiresAfter { get; } = Int32.TryParse(UtilityService.GetAppSetting("APIs:ExpiresAfter", "0"), out var expiresAfter) && expiresAfter > -1 ? expiresAfter : 0;

		public static int ServiceForwardersTimeout { get; } = Int32.TryParse(UtilityService.GetAppSetting("APIs:ServiceForwarders:Timeout", "180"), out var timeout) && timeout > 0 ? timeout : 180;

		public static bool ServiceForwardersAutoRedirect { get; } = "true".IsEquals(UtilityService.GetAppSetting("APIs:ServiceForwarders:AutoRedirect", "true"));

		public static List<string> ServiceForwardersExcludedHeaders { get; } = UtilityService.GetAppSetting("APIs:ServiceForwarders:ExcludedHeaders", "Host,Connection,Content-Type,Content-Encoding,Transfer-Encoding").ToList();

		public static string CaptchaKey { get; } = UtilityService.GetAppSetting("Keys:Captcha");

		public static bool TrackSessions { get; } = "true".IsEquals(UtilityService.GetAppSetting("Sessions:Track", "true")) && "true".IsEquals(UtilityService.GetAppSetting("Sessions:Track:APIs", "true"));
		#endregion

		public static async Task ProcessRequestAsync(HttpContext context)
		{
			// prepare the requesting information
			var isWebHookRequest = false;
			var header = context.Request.Headers.ToDictionary().Copy(RESTfulAPIs.ExcludedHeaders.Concat(context.Request.Headers.Keys.Where(name => name.IsStartsWith("cf-") || name.IsStartsWith("sec-"))));
			var query = context.Request.QueryString.ToDictionary(queryString =>
			{
				var pathSegments = context.GetRequestPathSegments();
				var serviceName = pathSegments.Length > 0 && !string.IsNullOrWhiteSpace(pathSegments[0])
					? pathSegments[0].GetANSIUri(false, true)
					: context.GetParameter("x-service-name") ?? context.GetParameter("ServiceName") ?? "";
				var objectName = pathSegments.Length > 1 && !string.IsNullOrWhiteSpace(pathSegments[1])
					? pathSegments[1].GetANSIUri(false, true)
					: context.GetParameter("x-object-name") ?? context.GetParameter("ObjectName") ?? "";
				var objectIdentity = pathSegments.Length > 2 && !string.IsNullOrWhiteSpace(pathSegments[2])
					? pathSegments[2].GetANSIUri(false, true)
					: context.GetParameter("x-object-identity") ?? context.GetParameter("ObjectIdentity") ?? "";
				if (serviceName.IsStartsWith("webhook") || serviceName.IsStartsWith("web-hook"))
				{					
					isWebHookRequest = true;
					objectName = objectIdentity = "";
					context.SetItem("Correlation-ID", context.GetParameter("x-original-correlation-id") ?? context.GetCorrelationID());
					header["x-webhook-type"] = pathSegments.Last().IsEquals("~test") ? "test" : pathSegments.Last().IsEquals("~forwarder") ? "forwarder" : "sync";
					header["x-webhook-uri"] = $"{context.GetRequestUri()}";
					header["x-webhook-service"] = serviceName = pathSegments.Length > 1 && !string.IsNullOrWhiteSpace(pathSegments[1])
						? pathSegments[1].GetANSIUri(false, true).GetCapitalizedFirstLetter()
						: context.GetParameter("x-service-name") ?? context.GetParameter("ServiceName") ?? "";
					if (pathSegments.Length > 2 && !string.IsNullOrWhiteSpace(pathSegments[2]))
						header["x-webhook-system"] = pathSegments[2].GetANSIUri();
					if (pathSegments.Length > 3 && !string.IsNullOrWhiteSpace(pathSegments[3]))
					{
						if (pathSegments[3].GetANSIUri().IsValidUUID())
							header["x-webhook-entity"] = pathSegments[3].GetANSIUri();
						else
							header["x-webhook-object"] = pathSegments[3].GetANSIUri(false, true).Replace("-", "").Replace("_", "");
					}
					if (pathSegments.Length > 4 && !string.IsNullOrWhiteSpace(pathSegments[4]))
						header["x-webhook-adapter"] = pathSegments[4].GetANSIUri().Replace("_", "");
				}
				queryString["service-name"] = serviceName;
				queryString["object-name"] = objectName;
				queryString["object-identity"] = objectIdentity;
			});
			var extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			if (query.Remove("x-request-extra", out var extraInfo) && !string.IsNullOrWhiteSpace(extraInfo))
				try
				{
					extra = extraInfo.Url64Decode().ToExpandoObject().ToDictionary(kvp => kvp.Key, kvp => kvp.Value?.ToString(), StringComparer.OrdinalIgnoreCase);
				}
				catch { }

			using var cts = CancellationTokenSource.CreateLinkedTokenSource(Global.CancellationToken, context.RequestAborted);
			bool isSessionProccessed = false, isSessionInitialized = false, isAccountProccessed = false, isActivationProccessed = false;
			var isDebugLogEnabled = Global.IsDebugResultsEnabled || context.ContainsKey("x-logs");
			var requestInfo = new RequestInfo(context.GetSession(), query["service-name"], query["object-name"], context.Request.Method, query, header)
			{
				Extra = extra,
				CorrelationID = context.GetCorrelationID()
			};

			// special: working with Users service
			if (requestInfo.ServiceName.IsEquals("Users"))
			{
				if (requestInfo.ObjectName.IsEquals("Session"))
				{
					isSessionProccessed = true;
					isSessionInitialized = requestInfo.Verb.IsEquals("GET");
					isAccountProccessed = requestInfo.Verb.IsEquals("POST");
				}
				else if (requestInfo.ObjectName.IsEquals("Account"))
					isAccountProccessed = requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT");
				else if (requestInfo.ObjectName.IsEquals("Activate"))
					isActivationProccessed = requestInfo.Verb.IsEquals("GET");
			}
			else if (requestInfo.ServiceName.IsStartsWith("Session") || requestInfo.ServiceName.IsStartsWith("Online") || requestInfo.ServiceName.IsStartsWith("Statistic") || requestInfo.ServiceName.IsStartsWith("Hit") || requestInfo.ServiceName.IsStartsWith("Visit") || requestInfo.ServiceName.IsStartsWith("Counter"))
			{
				requestInfo.ObjectName = requestInfo.ServiceName.IsStartsWith("Statistic") || requestInfo.ServiceName.IsStartsWith("Hit") || requestInfo.ServiceName.IsStartsWith("Visit") || requestInfo.ServiceName.IsStartsWith("Counter") ? "Statistics" : "Sessions";
				requestInfo.ServiceName = "Users";
			}

			// prepare authenticate token
			var gotAuthorizationToken = false;
			try
			{
				var authenticateToken = requestInfo.GetParameter("x-app-token");
				if (string.IsNullOrWhiteSpace(authenticateToken))
				{
					authenticateToken = context.GetHeaderParameter("authorization");
					if (authenticateToken != null)
					{
						requestInfo.Header.Remove("authorization");
						try
						{
							var isBasicToken = authenticateToken.IsStartsWith("Basic");
							authenticateToken = isBasicToken || authenticateToken.IsStartsWith("Bearer") || authenticateToken.IsStartsWith("JWT") ? authenticateToken.ToArray(" ").Last() : null;
							if (authenticateToken != null)
							{
								gotAuthorizationToken = true;
								var response = await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Token", "GET")
								{
									Query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
									Header = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
									{
										["x-authorization-token"] = authenticateToken,
										["x-authorization-mode"] = isBasicToken ? "Basic" : "Bearer",
										["x-authorization-signature"] = authenticateToken.GetHMACSHA256(Global.ValidationKey)
									},
									CorrelationID = requestInfo.CorrelationID
								}, cts.Token, RESTfulAPIs.Logger, "Authentications").ConfigureAwait(false);
								requestInfo.Header["x-app-token"] = authenticateToken = response.Get<string>("Token");
								requestInfo.Session.Fill(response.Get<JObject>("Session"));
							}
						}
						catch (Exception ex)
						{
							await context.WriteLogsAsync(RESTfulAPIs.Logger, "Authentications", $"Error occurred while authorizing with token => {ex.Message}", ex).ConfigureAwait(false);
							context.WriteError(RESTfulAPIs.Logger, ex, requestInfo, null, false);
							return;
						}
					}
				}

				// parse and update information from token
				var tokenIsRequired = !isWebHookRequest && !isActivationProccessed
					&& (!isSessionInitialized || !requestInfo.Session.User.ID.Equals("") && !requestInfo.Session.User.IsSystemAccount || requestInfo.Query.ContainsKey("register"))
					&& !RESTfulAPIs.NoTokenRequiredServices.Contains(requestInfo.ServiceName)
					&& !RESTfulAPIs.PrivateToken.IsEquals(requestInfo.GetParameter("x-private-token"));

				if (!string.IsNullOrWhiteSpace(authenticateToken))
				{
					if (!gotAuthorizationToken)
					{
						var expiresAfter = Int32.TryParse(context.GetParameter("x-app-token-expires"), out var expires) && expires > 0 ? expires : 0;
						await context.UpdateWithAuthenticateTokenAsync(requestInfo.Session, authenticateToken, expiresAfter > 0 ? expiresAfter : RESTfulAPIs.ExpiresAfter, null, null, null, RESTfulAPIs.Logger, "Authentications", requestInfo.CorrelationID).ConfigureAwait(false);
					}
				}
				else if (tokenIsRequired)
					throw new InvalidSessionException("Session is invalid (Token is not found)");

				// check session
				if (tokenIsRequired)
				{
					if (requestInfo.Query.TryGetValue("register", out var registered) && requestInfo.ServiceName.IsEquals("Users") && requestInfo.ObjectName.IsEquals("Session"))
					{
						if (!registered.IsEquals(await Global.Cache.GetAsync<string>(requestInfo.Session.SessionID.GetCacheKey<Session>(), cts.Token).ConfigureAwait(false)))
							throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
					}
					else if (!await context.IsSessionExistAsync(requestInfo.Session, RESTfulAPIs.Logger, "Authentications", requestInfo.CorrelationID).ConfigureAwait(false))
						throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
				}
			}
			catch (Exception ex)
			{
				context.WriteError(RESTfulAPIs.Logger, ex, requestInfo, null, false);
				if (isDebugLogEnabled)
					RESTfulAPIs.Logger.LogError(ex.Message, ex);
				return;
			}

			// prepare identities
			if (string.IsNullOrWhiteSpace(requestInfo.Session.SessionID))
				requestInfo.Session.SessionID = requestInfo.Session.User.SessionID = UtilityService.NewUUID;

			if (string.IsNullOrWhiteSpace(requestInfo.Session.DeviceID))
				requestInfo.Session.DeviceID = $"{UtilityService.NewUUID}@vieapps-ngx";

			// request body
			if (requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT") || requestInfo.Verb.IsEquals("PATCH"))
				try
				{
					requestInfo.Body = await context.ReadTextAsync(cts.Token).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					await context.WriteLogsAsync(RESTfulAPIs.Logger, "RESTfulAPIs", $"Error occurred while parsing body of the request => {ex.Message}", ex).ConfigureAwait(false);
				}

			else if (requestInfo.Verb.IsEquals("GET") && requestInfo.Query.Remove("x-body", out var encodedBody))
				try
				{
					requestInfo.Body = encodedBody.Url64Decode();
				}
				catch (Exception ex)
				{
					await context.WriteLogsAsync(RESTfulAPIs.Logger, "RESTfulAPIs", $"Error occurred while parsing body of the 'x-body' parameter => {ex.Message}", ex).ConfigureAwait(false);
				}

			// verify captcha
			try
			{
				requestInfo.CaptchaIsValid();
			}
			catch (Exception ex)
			{
				context.WriteError(RESTfulAPIs.Logger, ex, requestInfo, null, false);
				if (isDebugLogEnabled)
					RESTfulAPIs.Logger.LogError(ex.Message, ex);
				return;
			}

			// prepare related information when working with an account
			if (isAccountProccessed || "otp".IsEquals(requestInfo.ObjectName))
				try
				{
					requestInfo.PrepareAccountRelated((msg, ex) => context.WriteLogs(RESTfulAPIs.Logger, "RESTfulAPIs", msg, ex, Global.ServiceName, LogLevel.Error, requestInfo.CorrelationID));
				}
				catch (Exception ex)
				{
					context.WriteError(RESTfulAPIs.Logger, ex, requestInfo, null, false);
					if (isDebugLogEnabled)
						RESTfulAPIs.Logger.LogError(ex.Message, ex);
					return;
				}

			// update context
			context.SetSession(requestInfo.Session);
			context.User = new UserPrincipal(requestInfo.Session.User);

			// tracking
			if (!isSessionProccessed)
			{
				if (RESTfulAPIs.TrackSessions || gotAuthorizationToken)
					requestInfo.SendSessionState();
				else
					requestInfo.TrackStatistics();
			}

			// process request of sessions
			if (isSessionProccessed)
				switch (requestInfo.Verb)
				{
					case "GET":
						await context.RegisterSessionAsync(requestInfo, cts.Token).ConfigureAwait(false);
						break;

					case "POST":
						await context.LogSessionInAsync(requestInfo, cts.Token).ConfigureAwait(false);
						break;

					case "PUT":
						await context.LogOTPSessionInAsync(requestInfo, cts.Token).ConfigureAwait(false);
						break;

					case "DELETE":
						await context.LogSessionOutAsync(requestInfo, cts.Token).ConfigureAwait(false);
						break;

					default:
						context.WriteError(RESTfulAPIs.Logger, new MethodNotAllowedException(requestInfo.Verb), requestInfo, null, false);
						break;
				}

			// process request of activations
			else if (isActivationProccessed)
				await context.ActivateAsync(requestInfo, cts.Token).ConfigureAwait(false);

			// process request of web-hook messages
			else if (isWebHookRequest)
				try
				{
					if (requestInfo.Header.TryGetValue("x-webhook-type", out var webhookType) && webhookType.IsEquals("test"))
					{
						var response = new JObject
						{
							["URI"] = requestInfo.GetHeaderParameter("x-webhook-uri"),
							["Verb"] = requestInfo.Verb,
							["Header"] = requestInfo.Header.ToJObject(),
							["Query"] = requestInfo.Query.ToJObject(),
							["Body"] = requestInfo.BodyAsJson
						};
						await context.WriteLogsAsync(RESTfulAPIs.Logger, "WebHooks", $"Got a testing web-hook message [{requestInfo.GetHeaderParameter("x-webhook-uri")}] {response}").ConfigureAwait(false);
						await context.WriteAsync(response, cts.Token).ConfigureAwait(false);
					}
					else
					{
						var contentType = "application/json";
						var contentBody = "";
						var waitForCompleted = "GET".IsEquals(requestInfo.Verb) || (requestInfo.TryGetParameter("wait-for", out var wait) && wait.IsEquals("completed"));
						var webhook = requestInfo.GetService().ProcessWebHookMessageAsync(requestInfo, waitForCompleted ? cts.Token : Global.CancellationToken);
						JToken response = new JObject { ["Status"] = "OK" };
						if (waitForCompleted)
							try
							{
								response = await webhook.ConfigureAwait(false);
								contentType = response.Get<string>("Content-Type");
								contentBody = response.Get<string>("Content-Body");
							}
							catch (Exception ex)
							{
								await context.WriteLogsAsync(RESTfulAPIs.Logger, "WebHooks", $"Error occurred while processing a web-hook message => {ex.Message}", ex).ConfigureAwait(false);
							}
						else
							webhook.Run(ex => Global.WriteLogs(RESTfulAPIs.Logger, "WebHooks", $"Error occurred while processing a web-hook message => {ex.Message}", ex, Global.ServiceName, LogLevel.Error, requestInfo.CorrelationID));

						if (!string.IsNullOrWhiteSpace(contentType) && !"application/json".IsEquals(contentType) && !string.IsNullOrWhiteSpace(contentBody))
							await context.WriteAsync(contentType, response.Get<string>("Cache-Control"), contentBody.ToBytes(), cts.Token).ConfigureAwait(false);
						else
							await context.WriteAsync(response, cts.Token).ConfigureAwait(false);
					}
				}
				catch (Exception ex)
				{
					context.WriteError(RESTfulAPIs.Logger, ex, requestInfo);
				}

			// process request of discovery (controllers, services, definitions, resources, ...)
			else if (requestInfo.ServiceName.IsEquals("discovery"))
				try
				{
					var response = requestInfo.ObjectName.IsEquals("controllers")
						? RESTfulAPIs.GetControllers()
						: requestInfo.ObjectName.IsEquals("services")
							? RESTfulAPIs.GetServices()
							: requestInfo.ObjectName.IsEquals("definitions")
								? await context.CallServiceAsync(requestInfo.PrepareDefinitionRelated(), cts.Token, RESTfulAPIs.Logger, "Http.Definitions").ConfigureAwait(false)
								: throw new InvalidRequestException();
					await context.WriteAsync(response, cts.Token).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(RESTfulAPIs.Logger, ex, requestInfo);
				}

			// process request of logs
			else if (requestInfo.ServiceName.IsEquals("logs"))
				try
				{
					if (!context.IsAuthenticated())
						throw new AccessDeniedException();

					if (!requestInfo.Verb.IsEquals("GET"))
						throw new MethodNotAllowedException(requestInfo.Verb);

					requestInfo.ObjectName = "service";
					await context.WriteAsync(await Global.CallServiceAsync(requestInfo, cts.Token).ConfigureAwait(false), cts.Token).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(RESTfulAPIs.Logger, ex, requestInfo);
				}

			// process request to download a temporary file
			else if (requestInfo.ServiceName.IsEquals("temp.download"))
				try
				{
					if (requestInfo.Verb.IsEquals("GET"))
					{
						var fileName = await requestInfo.DownloadTemporaryFileAsync(cts.Token).ConfigureAwait(false);
						var fileInfo = new FileInfo(Path.Combine(UtilityService.GetAppSetting("Path:Temp", Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data-files", "temp")), fileName));
						await context.WriteAsync(fileInfo, fileName.Length > 33 && fileName.Left(32).IsValidUUID() ? fileName.Right(fileName.Length - 33) : fileName, null, cts.Token).ConfigureAwait(false);
					}
					else
						throw new MethodNotAllowedException(requestInfo.Verb);
				}
				catch (Exception ex)
				{
					context.WriteError(RESTfulAPIs.Logger, ex, requestInfo);
				}

			// process request of email
			else if ((requestInfo.ServiceName.IsEquals("email") || requestInfo.ServiceName.IsEquals("emails")) && "test".IsEquals(requestInfo.ObjectName))
				try
				{
					if (requestInfo.Verb.IsEquals("POST"))
					{
						var data = requestInfo.BodyAsExpandoObject;
						await new EmailMessage
						{
							ID = requestInfo.CorrelationID,
							From = data.Get<string>("Sender") ?? data.Get<string>("Smtp.User"),
							To = data.Get<string>("To"),
							Subject = data.Get("Subject", $"Testing email from {requestInfo.Session.IP}"),
							Body = data.Get("Body", $"Testing email from {requestInfo.Session.IP}"),
							Footer = data.Get<string>("Signature"),
							SmtpServer = data.Get<string>("Smtp.Host"),
							SmtpServerPort = data.Get("Smtp.Port", 25),
							SmtpServerEnableSsl = data.Get("Smtp.EnableSsl", false),
							SmtpUsername = data.Get<string>("Smtp.User"),
							SmtpPassword = data.Get<string>("Smtp.UserPassword")
						}.SendAsync(cts.Token).ConfigureAwait(false);
						await context.WriteAsync(new JObject { ["Status"] = "Success" }, cts.Token).ConfigureAwait(false);
					}
					else
						throw new MethodNotAllowedException(requestInfo.Verb);
				}
				catch (Exception ex)
				{
					context.WriteError(RESTfulAPIs.Logger, ex, requestInfo);
				}

			// process requests of pushers (broadcast message to clients)
			else if (requestInfo.ServiceName.IsEquals("pusher"))
				try
				{
					if (requestInfo.Verb.IsEquals("POST"))
					{
						new CommunicateMessage("APIGateway")
						{
							Type = "Broadcast#Client",
							Data = requestInfo.BodyAsJson.As<UpdateMessage>().ToJson()
						}.Send();
						await context.WriteAsync(new JObject { ["Status"] = "Success" }, cts.Token).ConfigureAwait(false);
					}
					else
						throw new InvalidRequestException();
				}
				catch (Exception ex)
				{
					context.WriteError(RESTfulAPIs.Logger, ex, requestInfo);
				}

			// flush caching storages
			else if (requestInfo.ServiceName.IsEquals("cache"))
				try
				{
					await context.WriteAsync(await requestInfo.FlushCachingStoragesAsync(cts.Token).ConfigureAwait(false), cts.Token).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(RESTfulAPIs.Logger, ex, requestInfo);
				}

			// process requests of forwarding services
			else if (RESTfulAPIs.ServiceForwarders.ContainsKey(requestInfo.ServiceName.ToLower()))
				try
				{
					await context.WriteAsync(await requestInfo.ForwardRequestAsync(cts.Token).ConfigureAwait(false), cts.Token).ConfigureAwait(false);
				}
				catch (RemoteServerException ex)
				{
					var (statusCode, body, headers) = requestInfo.GetForwardingRequestError(ex);
					if (isDebugLogEnabled)
						Global.Logger.LogError($"The remote service return an error\r\n- Code: {statusCode}\r\n- Body: {body}\r\n- Headers:\r\n\t{headers.ToString("\r\n\t", kvp => $"{kvp.Key}: {kvp.Value}")}\r\n", ex);
					context.WriteError(statusCode, body, headers);
				}
				catch (Exception ex)
				{
					if (isDebugLogEnabled)
						Global.Logger.LogError($"The remote service return an unexcpected => {ex.Message}", ex);
					context.WriteError(RESTfulAPIs.Logger, ex, requestInfo);
				}

			// process request of services
			else
				try
				{
					// prepare signature when work with accounts
					if (isAccountProccessed)
					{
						if (!requestInfo.Extra.ContainsKey("Signature"))
						{
							if (requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT"))
								requestInfo.Extra["Signature"] = requestInfo.Body.GetHMACSHA256(Global.ValidationKey);
							else if (requestInfo.TryGetParameter("x-app-token", out var authenticateToken))
								requestInfo.Extra["Signature"] = authenticateToken.GetHMACSHA256(Global.ValidationKey);
						}
					}

					// prepare signature when work with files
					else if (requestInfo.ServiceName.IsEquals("files"))
					{
						if (!requestInfo.Extra.ContainsKey("Signature"))
						{
							requestInfo.Extra["SessionID"] = requestInfo.Session.SessionID.GetHMACBLAKE256(Global.ValidationKey);
							if (requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT"))
								requestInfo.Extra["Signature"] = requestInfo.Body.GetHMACSHA256(Global.ValidationKey);
							else if (requestInfo.TryGetParameter("x-app-token", out var authenticateToken))
								requestInfo.Extra["Signature"] = authenticateToken.GetHMACSHA256(Global.ValidationKey);
						}
					}

					// process the request
					var response = requestInfo.Verb.IsEquals("PATCH")
						? "rollback".IsEquals(requestInfo.GetParameter("x-patch-mode"))
							? await requestInfo.RollbackAsync(cts.Token).ConfigureAwait(false)
							: "restore".IsEquals(requestInfo.GetParameter("x-patch-mode"))
								? await requestInfo.RestoreAsync(cts.Token).ConfigureAwait(false)
								: "sync".IsEquals(requestInfo.GetParameter("x-patch-mode"))
									? await context.SyncAsync(requestInfo, cts.Token).ConfigureAwait(false)
									: throw new InvalidRequestException()
						: await context.CallServiceAsync(requestInfo, cts.Token, RESTfulAPIs.Logger, "RESTfulAPIs").ConfigureAwait(false);
					await context.WriteAsync(response, cts.Token).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(RESTfulAPIs.Logger, ex, requestInfo);
				}
		}

		static async Task WriteAsync(this HttpContext context, string contentType, string cacheControl, byte[] body, CancellationToken cancellationToken)
		{
			context.SetResponseHeaders((int)HttpStatusCode.OK, new Dictionary<string, string>
			{
				["Content-Type"] = contentType ?? "application/json",
				["Cache-Control"] = cacheControl ?? "private, no-store, no-cache",
				["X-Node"] = Global.NodeID,
				["X-Correlation-ID"] = context.GetCorrelationID()
			});
			await context.Response.Body.WriteAsync(body, cancellationToken).ConfigureAwait(false);
		}

		static Task WriteAsync(this HttpContext context, JToken json, CancellationToken cancellationToken)
			=> context.WriteAsync(null, null, json.ToString(RESTfulAPIs.JsonFormat).ToBytes(), cancellationToken);

		#region Create/Renew a session
		static async Task CreateOrRenewSessionAsync(this HttpContext context, RequestInfo requestInfo, JToken session = null, bool sendSessionState = true)
		{
			// call the service of users to create/renew session
			var body = (session ?? requestInfo.Session.GetSessionBody()).ToString(Formatting.None);
			await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "POST")
			{
				Body = body,
				Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
				{
					{ "Signature", body.GetHMACSHA256(Global.ValidationKey) }
				},
				CorrelationID = requestInfo.CorrelationID
			}, Global.CancellationToken, RESTfulAPIs.Logger, "Authentications").ConfigureAwait(false);

			// session state
			requestInfo.SendSessionState(true, sendSessionState);
		}
		#endregion

		#region Register a session
		static async Task RegisterSessionAsync(this HttpContext context, RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			// session of visitor/system account
			if (requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.IsSystemAccount)
				try
				{
					// initialize session
					var cacheKey = requestInfo.Session.SessionID.GetCacheKey<Session>();
					if (!requestInfo.ContainsKey("register"))
					{
						// generate device identity
						if (string.IsNullOrWhiteSpace(requestInfo.Session.DeviceID))
							requestInfo.Session.DeviceID = (requestInfo.Session.AppName + "/" + requestInfo.Session.AppPlatform + "@" + (requestInfo.Session.AppAgent ?? "N/A")).GetHMACBLAKE128(requestInfo.Session.SessionID, true) + "@vieapps-ngx";

						// store identity into cache for further use
						await Global.Cache.SetAsync(cacheKey, requestInfo.Session.GetEncryptedID(), 13, cancellationToken).ConfigureAwait(false);
					}

					// register session
					else
					{
						// validate
						var registered = await Global.Cache.GetAsync<string>(cacheKey, cancellationToken).ConfigureAwait(false);
						var requested = requestInfo.Query["register"];
						if (!requested.IsEquals(registered))
						{
							var ex = new InvalidSessionException("Session is invalid (The session is not issued by the system)");
							if (Global.IsDebugResultsEnabled)
								await context.WriteLogsAsync(RESTfulAPIs.Logger, "Authentications", $"{ex.Message} => Registered: {registered} - Requested (encrypted): {requested}", ex);
							throw ex;
						}

						requested = requestInfo.Session.GetDecryptedID(requested, Global.EncryptionKey, Global.ValidationKey);
						if (!requestInfo.Session.SessionID.IsEquals(requested))
						{
							var ex = new InvalidSessionException("Session is invalid (The session is not issued by the system)");
							if (Global.IsDebugResultsEnabled)
								await context.WriteLogsAsync(RESTfulAPIs.Logger, "Authentications", $"{ex.Message} => Current: {requestInfo.Session.SessionID} - Requested (decrypted): {requested}", ex);
							throw ex;
						}

						// register the new session
						await Task.WhenAll
						(
							context.CreateOrRenewSessionAsync(requestInfo),
							Global.Cache.RemoveAsync(cacheKey, cancellationToken)
						).ConfigureAwait(false);
					}

					// response
					var response = requestInfo.Session.GetSessionJson();
					await Task.WhenAll
					(
						context.WriteAsync(response, cancellationToken),
						!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(RESTfulAPIs.Logger, "Authentications",
						[
							$"Successfully process request of session (registration of anonymous user)",
							$"- Request: {requestInfo.ToJson().ToString(RESTfulAPIs.JsonFormat)}",
							$"- Response: {response.ToJson().ToString(RESTfulAPIs.JsonFormat)}",
							$"- Execution times: {context.GetExecutionTimes()}"
						])
					).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(RESTfulAPIs.Logger, ex, requestInfo, null, false);
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
							{ "Signature", requestInfo.GetParameter("x-app-token").GetHMACSHA256(Global.ValidationKey) }
						},
						CorrelationID = requestInfo.CorrelationID
					}, cancellationToken, RESTfulAPIs.Logger, "Authentications").ConfigureAwait(false) ?? throw new SessionNotFoundException();
					if (!requestInfo.Session.User.ID.IsEquals(session.Get<string>("UserID")))
						throw new InvalidTokenException();

					// update session
					requestInfo.UpdateSessionBody(session);
					await context.CreateOrRenewSessionAsync(requestInfo, session).ConfigureAwait(false);

					// response
					var response = requestInfo.GetSessionJson();
					await Task.WhenAll
					(
						context.WriteAsync(response, cancellationToken),
						!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(RESTfulAPIs.Logger, "Authentications",
						[
							$"Successfully process request of session (registration of authenticated user)",
							$"- Request: {requestInfo.ToJson().ToString(RESTfulAPIs.JsonFormat)}",
							$"- Response: {response.ToJson().ToString(RESTfulAPIs.JsonFormat)}",
							$"- Execution times: {context.GetExecutionTimes()}"
						])
					).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					context.WriteError(RESTfulAPIs.Logger, ex, requestInfo, null, true, "Authentications");
				}
		}
		#endregion

		#region Log a session in
		static async Task LogSessionInAsync(this HttpContext context, RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			try
			{
				// prepare
				var account = requestInfo.Extra != null && requestInfo.Extra.TryGetValue("Account", out var extAccount)
					? extAccount
					: requestInfo.Extra != null && requestInfo.Extra.TryGetValue("Email", out var extEmail)
						? extEmail
						: null;

				var password = requestInfo.Extra != null && requestInfo.Extra.TryGetValue("Password", out var extPassword)
					? extPassword
					: null;

				if (string.IsNullOrWhiteSpace(account) || string.IsNullOrWhiteSpace(password))
					throw new InvalidDataException("Request JSON is invalid (account/password must be encrypted by RSA before sending)");

				// call service to perform log in
				var body = new JObject
				{
					{ "Account", account },
					{ "Password", password },
				}.ToString(Formatting.None);

				var response = await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "PUT", requestInfo.Query)
				{
					Body = body,
					Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "Signature", body.GetHMACSHA256(Global.ValidationKey) }
					},
					CorrelationID = requestInfo.CorrelationID
				}, cancellationToken, RESTfulAPIs.Logger, "Authentications").ConfigureAwait(false);

				// two-factors authentication
				var require2FA = response.Get("Require2FA", false);

				if (require2FA)
					response = new JObject
					{
						{ "ID", response.Get<string>("ID") },
						{ "Require2FA", true },
						{ "Providers", response["Providers"] as JArray }
					};

				else
				{
					// update state of current (means old session)
					var oldSessionID = requestInfo.Session.SessionID;
					requestInfo.SendSessionState(false, false, true);

					// register new session
					requestInfo.Session.User = response.Copy<User>();
					requestInfo.Session.User.SessionID = requestInfo.Session.SessionID = UtilityService.NewUUID;
					await context.CreateOrRenewSessionAsync(requestInfo).ConfigureAwait(false);

					response = requestInfo.GetSessionJson(null, payload => payload["did"] = requestInfo.Session.DeviceID);
					new CommunicateMessage("APIGateway")
					{
						Type = "Session#Patch",
						Data = new JObject
						{
							{ "SessionID", oldSessionID },
							{ "EncryptedID", response["ID"] },
							{ "AuthenticateToken", response["Token"] }
						}
					}.Send();
				}

				// response
				await Task.WhenAll
				(
					context.WriteAsync(response, cancellationToken),
					Global.Cache.RemoveAsync($"Attempt#{context.GetRemoteIPAddress()}", cancellationToken),
					!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(RESTfulAPIs.Logger, "Authentications",
					[
						$"Successfully process request of session (sign-in)",
						$"- Request: {requestInfo.ToJson().ToString(RESTfulAPIs.JsonFormat)}",
						$"- Response: {response.ToJson().ToString(RESTfulAPIs.JsonFormat)}",
						$"- Execution times: {context.GetExecutionTimes()}"
					])
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await context.WaitOnAttemptedAsync().ConfigureAwait(false);
				context.WriteError(RESTfulAPIs.Logger, ex, requestInfo, null, true, "Authentications");
			}
		}
		#endregion

		#region Log a session in with OTP
		static async Task LogOTPSessionInAsync(this HttpContext context, RequestInfo requestInfo, CancellationToken cancellationToken)
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

				// call service to log in
				var response = await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "OTP", "POST", requestInfo.Query)
				{
					Body = new JObject
					{
						{ "ID", id.Encrypt(Global.EncryptionKey) },
						{ "OTP", otp.Encrypt(Global.EncryptionKey) },
						{ "Info", info.Encrypt(Global.EncryptionKey) }
					}.ToString(Formatting.None),
					CorrelationID = requestInfo.CorrelationID
				}, cancellationToken, RESTfulAPIs.Logger, "Authentications").ConfigureAwait(false);

				// update state of current (means old session)
				var oldSessionID = requestInfo.Session.SessionID;
				requestInfo.SendSessionState(false, false, true);

				// register new session
				requestInfo.Session.User = response.Copy<User>();
				requestInfo.Session.User.SessionID = requestInfo.Session.SessionID = UtilityService.NewUUID;
				requestInfo.Session.Verified = true;
				await context.CreateOrRenewSessionAsync(requestInfo).ConfigureAwait(false);

				response = requestInfo.GetSessionJson(null, payload => payload["did"] = requestInfo.Session.DeviceID);
				new CommunicateMessage("APIGateway")
				{
					Type = "Session#Patch",
					Data = new JObject
					{
						{ "SessionID", oldSessionID },
						{ "EncryptedID", response["ID"] },
						{ "AuthenticateToken", response["Token"] }
					}
				}.Send();

				// response
				await Task.WhenAll
				(
					context.WriteAsync(response, cancellationToken),
					Global.Cache.RemoveAsync($"Attempt#{context.GetRemoteIPAddress()}", cancellationToken),
					Global.IsDebugResultsEnabled ? context.WriteLogsAsync(RESTfulAPIs.Logger, "Authentications",
					[
						$"Successfully process request of session (OTP validation)",
						$"- Request: {requestInfo.ToJson().ToString(RESTfulAPIs.JsonFormat)}",
						$"- Response: {response.ToJson().ToString(RESTfulAPIs.JsonFormat)}",
						$"- Execution times: {context.GetExecutionTimes()}"
					]) : Task.CompletedTask
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await context.WaitOnAttemptedAsync().ConfigureAwait(false);
				context.WriteError(RESTfulAPIs.Logger, ex, requestInfo, null, true, "Authentications");
			}
		}
		#endregion

		#region Log a session out
		static async Task LogSessionOutAsync(this HttpContext context, RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			try
			{
				// check
				if (requestInfo.Session.User.ID.Equals("") || requestInfo.Session.User.IsSystemAccount)
					throw new InvalidRequestException();

				// call service to perform log out
				await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "DELETE", requestInfo.Query, requestInfo.Header)
				{
					Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						["Signature"] = requestInfo.GetParameter("x-app-token")?.GetHMACSHA256(Global.ValidationKey)
					},
					CorrelationID = requestInfo.CorrelationID
				}, cancellationToken, RESTfulAPIs.Logger, "Authentications").ConfigureAwait(false);

				// update state of current (means old session)
				var oldSessionID = requestInfo.Session.SessionID;
				requestInfo.SendSessionState(false, false, true);

				// prepare new session
				requestInfo.Session.SessionID = UtilityService.NewUUID;
				requestInfo.Session.User = new User("", requestInfo.Session.SessionID, [SystemRole.All.ToString()], []);
				requestInfo.Session.Verified = false;
				await Task.WhenAll
				(
					context.CreateOrRenewSessionAsync(requestInfo, null, false),
					Global.Cache.SetAsync(requestInfo.Session.SessionID.GetCacheKey<Session>(), requestInfo.Session.GetEncryptedID(), 13, cancellationToken)
				).ConfigureAwait(false);

				var response = requestInfo.GetSessionJson(null, payload => payload["did"] = requestInfo.Session.DeviceID);
				new CommunicateMessage("APIGateway")
				{
					Type = "Session#Patch",
					Data = new JObject
					{
						{ "SessionID", oldSessionID },
						{ "EncryptedID", response["ID"] },
						{ "AuthenticateToken", response["Token"] }
					}
				}.Send();

				// response
				await Task.WhenAll
				(
					context.WriteAsync(response, cancellationToken),
					!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(RESTfulAPIs.Logger, "Authentications", 
					[
						$"Successfully process request of session (sign-out)",
						$"- Request: {requestInfo.ToJson().ToString(RESTfulAPIs.JsonFormat)}",
						$"- Response: {response.ToJson().ToString(RESTfulAPIs.JsonFormat)}",
						$"- Execution times: {context.GetExecutionTimes()}"
					])
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				context.WriteError(RESTfulAPIs.Logger, ex, requestInfo, null, true, "Authentications");
			}
		}
		#endregion

		#region Activation
		static async Task ActivateAsync(this HttpContext context, RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			try
			{
				// prepare device identity
				if (string.IsNullOrWhiteSpace(requestInfo.Session.DeviceID))
					requestInfo.Session.DeviceID = (requestInfo.Session.AppName + "/" + requestInfo.Session.AppPlatform + "@" + (requestInfo.Session.AppAgent ?? "N/A")).GetHMACSHA384(requestInfo.Session.SessionID, true) + "@vieapps-ngx";

				// call service to activate
				var response = await context.CallServiceAsync(new RequestInfo(requestInfo)
				{
					ServiceName = "Users",
					ObjectName = "Activate",
					Verb = "GET"
				}, cancellationToken, RESTfulAPIs.Logger, "Authentications").ConfigureAwait(false);

				// get user information & register the session
				requestInfo.Session.User = response.Copy<User>();
				requestInfo.Session.User.SessionID = requestInfo.Session.SessionID = UtilityService.NewUUID;
				await context.CreateOrRenewSessionAsync(requestInfo).ConfigureAwait(false);

				// response
				response = requestInfo.GetSessionJson(null, payload => payload["did"] = requestInfo.Session.DeviceID);
				await Task.WhenAll
				(
					context.WriteAsync(response, cancellationToken),
					!Global.IsDebugResultsEnabled ? Task.CompletedTask : context.WriteLogsAsync(RESTfulAPIs.Logger, "Authentications",
					[
						$"Successfully process request of session (activation)",
						$"- Request: {requestInfo.ToJson().ToString(RESTfulAPIs.JsonFormat)}",
						$"- Response: {response.ToJson().ToString(RESTfulAPIs.JsonFormat)}",
						$"- Execution times: {context.GetExecutionTimes()}"
					])
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				context.WriteError(RESTfulAPIs.Logger, ex, requestInfo, null, true, "Authentications");
			}
		}
		#endregion

		#region Process rollback/restore/sync requests
		internal static Task<JToken> RollbackAsync(this RequestInfo requestInfo, CancellationToken cancellationToken)
			=> net.vieapps.Services.Router.GetService(requestInfo.ServiceName)?.ProcessRollbackRequestAsync(requestInfo, cancellationToken) ?? Task.FromException<JToken>(new ServiceNotFoundException());

		internal static Task<JToken> RestoreAsync(this RequestInfo requestInfo, CancellationToken cancellationToken)
			=> net.vieapps.Services.Router.GetService(requestInfo.ServiceName)?.ProcessRestoreRequestAsync(requestInfo, cancellationToken) ?? Task.FromException<JToken>(new ServiceNotFoundException());

		static async Task<JToken> SyncAsync(this HttpContext context, RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			Exception exception = null;
			var overallWatch = Stopwatch.StartNew();
			var callingWatch = Stopwatch.StartNew();
			var developerID = requestInfo.Session?.DeveloperID ?? context.GetSession(requestInfo.Session?.SessionID, requestInfo.Session?.User)?.DeveloperID;
			var appID = requestInfo.Session?.AppID ?? context.GetSession(requestInfo.Session?.SessionID, requestInfo.Session?.User)?.AppID;
			try
			{
				if (Global.IsDebugResultsEnabled)
					await context.WriteLogsAsync(developerID, appID, RESTfulAPIs.Logger, "Sync", [$"Start call service for synchronizing {requestInfo.Verb} {requestInfo.GetURI()} - {requestInfo.Session.AppName} ({requestInfo.Session.AppMode.ToLower()} app) - {requestInfo.Session.AppPlatform} @ {requestInfo.Session.IP}"], null, Global.ServiceName, LogLevel.Information, requestInfo.CorrelationID);

				callingWatch = Stopwatch.StartNew();
				var json = await requestInfo.SyncAsync(cancellationToken).ConfigureAwait(false);
				callingWatch.Stop();

				if (Global.IsDebugResultsEnabled)
					await context.WriteLogsAsync(developerID, appID, RESTfulAPIs.Logger, "Sync", ["Call service for synchronizing successful" + "\r\n" +
						$"- Request: {requestInfo.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" + "\r\n" +
						$"- Response: {json?.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"]
					, null, Global.ServiceName, LogLevel.Information, requestInfo.CorrelationID).ConfigureAwait(false);

				return json;
			}
			catch (WampSharp.V2.Client.WampSessionNotEstablishedException)
			{
				await Task.Delay(567, cancellationToken).ConfigureAwait(false);
				try
				{
					var json = await requestInfo.SyncAsync(cancellationToken).ConfigureAwait(false);
					callingWatch.Stop();

					if (Global.IsDebugResultsEnabled)
						await context.WriteLogsAsync(developerID, appID, RESTfulAPIs.Logger, "Sync", ["Re-call service for synchronizing successful" + "\r\n" +
							$"- Request: {requestInfo.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" + "\r\n" +
							$"- Response: {json?.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"]
						, null, Global.ServiceName, LogLevel.Information, requestInfo.CorrelationID).ConfigureAwait(false);

					return json;
				}
				catch (Exception)
				{
					throw;
				}
			}
			catch (Exception ex)
			{
				callingWatch.Stop();
				exception = ex;
				throw;
			}
			finally
			{
				overallWatch.Stop();
				if (Global.IsDebugResultsEnabled)
					await context.WriteLogsAsync(developerID, appID, RESTfulAPIs.Logger, "Sync", [$"Call service for synchronizing finished in {callingWatch.GetElapsedTimes()} - Overall: {overallWatch.GetElapsedTimes()}"], exception, Global.ServiceName, exception == null ? LogLevel.Information : LogLevel.Error, requestInfo.CorrelationID, exception == null ? null : $"Request: {requestInfo.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}").ConfigureAwait(false);
			}
		}
		#endregion

		#region Process requests of forwarding services
		static IEnumerable<string> ForwardingExcludedHeaders { get; } = ["Host", "Connection"];

		public static async Task<JToken> ForwardRequestAsync(this RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			var stopwatch = Stopwatch.StartNew();
			var info = RESTfulAPIs.ServiceForwarders[requestInfo.ServiceName.ToLower()];
			var forwarder = info.Type.CreateInstance() as ServiceForwarder;
			var endpointURL = await forwarder.PrepareAsync(requestInfo, info.EndpointURL, info.DataSource, cancellationToken).ConfigureAwait(false);
			if (string.IsNullOrWhiteSpace(endpointURL) || (!endpointURL.IsStartsWith("https://") && !endpointURL.IsStartsWith("http://")))
				throw new InformationInvalidException($"End-point URL is invalid [{info.EndpointURL}] => {endpointURL ?? "(null)"}");

			var headers = requestInfo.Header.Copy(ForwardingExcludedHeaders, dictionary =>
			{
				dictionary["AllowAutoRedirect"] = RESTfulAPIs.ServiceForwardersAutoRedirect.ToString();
				dictionary["User-Agent"] = requestInfo.GetAppAgent();
			});
			var body = requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT") || requestInfo.Verb.IsEquals("PATCH") ? requestInfo.Body : null;
			if (Global.IsDebugLogEnabled)
				await Global.WriteLogsAsync("Http.Forwards", $"Forward the request to a remote service [{requestInfo.Verb}: {endpointURL}]\r\n- IP: {requestInfo.Session.IP}\r\n- Headers:\r\n\t{headers.ToString("\r\n\t", kvp => $"{kvp.Key}: {kvp.Value}")}\r\n- Body: {body ?? "None"}").ConfigureAwait(false);

			using var webResponse = await new Uri(endpointURL).SendHttpRequestAsync(requestInfo.Verb, headers, body, RESTfulAPIs.ServiceForwardersTimeout, cancellationToken).ConfigureAwait(false);
			body = await webResponse.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

			var response = await forwarder.NormalizeAsync(requestInfo, body.ToJson(), cancellationToken).ConfigureAwait(false);
			if (Global.IsDebugLogEnabled)
				await Global.WriteLogsAsync("Http.Forwards", $"Forwarding request is completed - Execution times: {stopwatch.GetElapsedTimes()}\r\n- Response: {response.ToString(RESTfulAPIs.JsonFormat)}").ConfigureAwait(false);
			return response;
		}

		public static (int StatusCode, JToken Body, Dictionary<string, string> Headers) GetForwardingRequestError(this RequestInfo requestInfo, RemoteServerException exception)
		{
			var statusCode = exception.StatusCode;
			var body = new JObject
			{
				["Message"] = statusCode == HttpStatusCode.NotFound ? "Not found" : exception.Message,
				["Type"] = statusCode == HttpStatusCode.NotFound ? "InformationNotFoundException" : exception.GetTypeName(true),
				["Code"] = (int)statusCode,
				["Verb"] = requestInfo.Verb,
				["StackTrace"] = exception.GetStacks()
			};
			if (exception.Body != null)
				try
				{
					body = (exception.Body ?? "{}").ToJson() as JObject;
					var stacks = body.Get<JArray>("StackTrace");
					if (stacks == null)
						body["StackTrace"] = exception.GetStacks();
					else
					{
						var inner = exception.InnerException;
						while (inner != null)
						{
							stacks.Add($"{inner.Message} [{inner.GetType()}] {inner.StackTrace}");
							inner = inner.InnerException;
						}
					}
				}
				catch
				{
					body.Get<JArray>("StackTrace").Add(UtilityService.RemoveHTMLWhitespaces(exception.Body));
				}
			body["CorrelationID"] = requestInfo.CorrelationID;
			return ((int)statusCode, body, requestInfo.Header.Copy(RESTfulAPIs.ServiceForwardersExcludedHeaders));
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

			if (!CaptchaService.IsCodeValid(registered, input, RESTfulAPIs.CaptchaKey))
				throw new InvalidRequestException("Captcha code is invalid");

			return requestInfo;
		}

		public static RequestInfo PrepareAccountRelated(this RequestInfo requestInfo, Action<string, Exception> onParseError = null)
		{
			// prepare body
			var requestBody = requestInfo.GetBodyExpando() ?? throw new InvalidRequestException("Request is invalid (empty)");

			// prepare account/email
			var account = requestBody.Get<string>("Account");
			if (!string.IsNullOrWhiteSpace(account))
				try
				{
					account = Global.RSA.Decrypt(account);
					requestInfo.Extra["Account"] = account.Encrypt(Global.EncryptionKey);
				}
				catch (Exception ex)
				{
					throw new InvalidRequestException("Request is invalid (email must be encrypted by RSA before sending)", ex);
				}

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

			// prepare OTP
			var otpType = requestBody.Get<string>("OtpType");
			if (!string.IsNullOrWhiteSpace(otpType))
				try
				{
					otpType = Global.RSA.Decrypt(otpType);
					requestInfo.Extra["OtpType"] = otpType.Encrypt(Global.EncryptionKey);
				}
				catch (Exception ex)
				{
					onParseError?.Invoke($"Error occurred while parsing OTP Info => {ex.Message}", ex);
				}

			var otpPhone = requestBody.Get<string>("OtpPhone");
			if (!string.IsNullOrWhiteSpace(otpPhone))
				try
				{
					otpPhone = Global.RSA.Decrypt(otpPhone);
					requestInfo.Extra["OtpPhone"] = otpPhone.Encrypt(Global.EncryptionKey);
				}
				catch (Exception ex)
				{
					onParseError?.Invoke($"Error occurred while parsing OTP Info => {ex.Message}", ex);
				}

			var otpCode = requestBody.Get<string>("OtpCode");
			if (!string.IsNullOrWhiteSpace(otpCode))
				try
				{
					otpCode = Global.RSA.Decrypt(otpCode);
					requestInfo.Extra["OtpCode"] = otpCode.Encrypt(Global.EncryptionKey);
				}
				catch (Exception ex)
				{
					onParseError?.Invoke($"Error occurred while parsing OTP Info => {ex.Message}", ex);
				}

			var otpIssuer = requestBody.Get<string>("OtpIssuer");
			if (!string.IsNullOrWhiteSpace(otpIssuer))
				try
				{
					otpIssuer = Global.RSA.Decrypt(otpIssuer);
					requestInfo.Extra["OtpIssuer"] = otpIssuer.Encrypt(Global.EncryptionKey);
				}
				catch (Exception ex)
				{
					onParseError?.Invoke($"Error occurred while parsing OTP Info => {ex.Message}", ex);
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
				if (requestInfo.ServiceName.IsEquals("users") && requestInfo.ObjectName.IsEquals("account") && requestInfo.Verb.IsEquals("POST") && !requestInfo.Header.ContainsKey("x-captcha"))
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
				if (string.IsNullOrWhiteSpace(account) && string.IsNullOrWhiteSpace(email))
					throw new InvalidRequestException("Request is invalid (email is null or empty)");
			}

			// prepare to reew password via phone
			else if ("renew".IsEquals(objectIdentity))
			{
				if (string.IsNullOrWhiteSpace(account))
					throw new InvalidRequestException("Request is invalid (account is null or empty)");
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

		#region Helper: controllers, services, caching storages
		public static JToken GetControllers()
			=> RESTfulAPIs.Controllers.Values.Select(info => new JObject
			{
				{ "ID", info.Get<string>("ID").GenerateUUID() },
				{ "Platform", info.Get<string>("Platform") },
				{ "Available" , info.Get<bool>("Available") }
			})
			.ToJArray();

		public static JToken GetServices()
			=> RESTfulAPIs.Services.Values.Select(info => new
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

		public static async Task<JToken> FlushCachingStoragesAsync(this RequestInfo requestInfo, CancellationToken cancellationToken)
		{
			if (!requestInfo.ObjectName.IsEquals("flush") && !requestInfo.ObjectName.IsEquals("clear"))
				throw new InvalidRequestException();

			var isSystemAdministrator = requestInfo.Session.User.IsSystemAdministrator;
			if (!isSystemAdministrator)
			{
				var response = await Global.CallServiceAsync(new RequestInfo(new Session { User = requestInfo.Session.User }, "Users", "Account", "GET")
				{
					Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "IsSystemAdministrator", "" }
					},
					CorrelationID = requestInfo.CorrelationID
				}, cancellationToken).ConfigureAwait(false);
				isSystemAdministrator = requestInfo.Session.User.ID.IsEquals(response.Get<string>("ID")) && response.Get<bool>("IsSystemAdministrator");
			}
			if (!isSystemAdministrator)
				throw new AccessDeniedException();

			await Global.Cache.FlushAllAsync(cancellationToken).ConfigureAwait(false);
			return new JObject { ["Status"] = "Success" };
		}
		#endregion

		#region Helper: process inter-communicate messages
		static IEnumerable<string> ControllerAttributes { get; } = ["User", "Host", "Platform", "Mode", "Available", "Timestamp"];

		public static async Task ProcessInterCommunicateMessageAsync(CommunicateMessage message)
		{
			// send information of this service
			if (message.Type.IsEquals("Service#RequestInfo"))
				await Global.SendServiceInfoAsync("RESTfulAPIs").ConfigureAwait(false);

			// update information of a service
			else if (message.Type.IsEquals("Service#Info"))
			{
				var name = message.Data.Get<string>("Name");
				if (!RESTfulAPIs.Services.TryGetValue(name, out var services))
					RESTfulAPIs.Services.TryAdd(name, [message.Data as JObject]);
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
				if (RESTfulAPIs.Controllers.TryGetValue(id, out var controller))
				{
					controller["Available"] = false;
					var controllerID = controller.Get<string>("ID");
					RESTfulAPIs.Services.ForEach(kvp =>
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
				if (RESTfulAPIs.Controllers.TryGetValue(id, out var controller))
					ControllerAttributes.ForEach(name => controller[name] = message.Data[name]);
				else
					RESTfulAPIs.Controllers.TryAdd(id, message.Data as JObject);
			}

			// broadcast message to connected clients
			else if (message.Type.IsEquals("Broadcast#Client"))
				await WebSocketAPIs.BroadcastAsync(new UpdateMessage
				{
					DeviceID = message.Data.Get("DeviceID", "*"),
					ExcludedDeviceID = message.Data.Get("ExcludedDeviceID", ""),
					Type = message.Data.Get<string>("Type"),
					Data = message.Data.Get<JToken>("Data")
				}).ConfigureAwait(false);

			// broadcast message to service instances
			else if (message.Type.IsEquals("Broadcast#Service"))
				new CommunicateMessage
				{
					ServiceName = message.Data.Get<string>("ServiceName"),
					ExcludedNodeID = message.Data.Get<string>("ExcludedNodeID"),
					Type = message.Data.Get<string>("Type"),
					Data = message.Data.Get<JToken>("Data")
				}.Send();
		}
		#endregion

	}
}