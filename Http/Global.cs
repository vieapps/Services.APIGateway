#region Related components
using System;
using System.Net;
using System.Text;
using System.Web;
using System.IO;
using System.IO.Compression;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Reactive.Subjects;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using WampSharp.V2.Core.Contracts;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Caching;

using net.vieapps.Services.Base.AspNet;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public static partial class Global
	{

		#region Attributes
		static ISubject<UpdateMessage> UpdateMessagePublisher = null;
		static IDisposable InterCommunicateMessageUpdater = null;
		static HashSet<string> QueryExcluded = "service-name,object-name,object-identity,request-of-static-resource".ToHashSet();
		static Cache _Cache = null;

		internal static Cache Cache
		{
			get
			{
				return Global._Cache ?? (Global._Cache = new Cache("VIEApps-API-Gateway", UtilityService.GetAppSetting("Cache:ExpirationTime", "120").CastAs<int>(), UtilityService.GetAppSetting("Cache:Provider")));
			}
		}
		#endregion

		#region Start/End the app
		internal static void OnAppStart(HttpContext context)
		{
			var stopwatch = new Stopwatch();
			stopwatch.Start();

			// Json.NET
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings()
			{
				Formatting = Formatting.Indented,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			// default service name
			Base.AspNet.Global.ServiceName = "APIGateway";
			var correlationID = Base.AspNet.Global.GetCorrelationID(context?.Items);

			// open WAMP channels
			Task.Run(async () =>
			{
				await Base.AspNet.Global.OpenChannelsAsync(
					(sender, args) =>
					{
						Global.InterCommunicateMessageUpdater = Base.AspNet.Global.IncommingChannel.RealmProxy.Services
							.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages.apigateway")
							.Subscribe(
								async (message) =>
								{
									var relatedID = Base.AspNet.Global.GetCorrelationID();
									try
									{
										await Global.ProcessInterCommunicateMessageAsync(message).ConfigureAwait(false);
										await Task.WhenAll(
											Base.AspNet.Global.WriteDebugLogsAsync(relatedID, Base.AspNet.Global.ServiceName, $"Process an inter-communicate message successful\r\n{message?.ToJson().ToString(Base.AspNet.Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"),
											Base.AspNet.Global.IsDebugLogEnabled ? Base.AspNet.Global.WriteLogsAsync(relatedID, "RTU", $"Process an inter-communicate message successful\r\n{message?.ToJson().ToString(Formatting.Indented)}") : Task.CompletedTask
										).ConfigureAwait(false);
									}
									catch (Exception ex)
									{
										await Task.WhenAll(
											Base.AspNet.Global.WriteDebugLogsAsync(relatedID, Base.AspNet.Global.ServiceName, $"Error occurred while processing an inter-communicate message\r\n{message?.ToJson().ToString(Base.AspNet.Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}", ex),
											Base.AspNet.Global.WriteLogsAsync(relatedID, "RTU", $"Error occurred while processing an inter-communicate message\r\n{message?.ToJson().ToString(Base.AspNet.Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}", ex)
										).ConfigureAwait(false);
									}
								},
								async (exception) =>
								{
									var relatedID = Base.AspNet.Global.GetCorrelationID();
									await Task.WhenAll(
										Base.AspNet.Global.WriteDebugLogsAsync(relatedID, Base.AspNet.Global.ServiceName, "Error occurred while fetching inter-communicate message", exception),
										Base.AspNet.Global.WriteLogsAsync(relatedID, "RTU", "Error occurred while fetching inter-communicate message", exception)
									).ConfigureAwait(false);
								}
							);
					},
					(sender, args) =>
					{
						Task.Run(async () =>
						{
							var relatedID = Base.AspNet.Global.GetCorrelationID();
							try
							{
								await Task.WhenAll(
									Base.AspNet.Global.InitializeLoggingServiceAsync(),
									Base.AspNet.Global.InitializeRTUServiceAsync()
								).ConfigureAwait(false);
								await Task.WhenAll(
									Base.AspNet.Global.WriteDebugLogsAsync(relatedID, "RTU", "Initializing helper services succesful"),
									Base.AspNet.Global.WriteLogsAsync(relatedID, "RTU", "Initializing helper services succesful")
								).ConfigureAwait(false);
							}
							catch (Exception ex)
							{
								await Task.WhenAll(
									Base.AspNet.Global.WriteDebugLogsAsync(relatedID, "RTU", "Error occurred while initializing helper services", ex),
									Base.AspNet.Global.WriteLogsAsync(relatedID, "RTU", "Error occurred while initializing helper services", ex)
								).ConfigureAwait(false);
							}
						}).ConfigureAwait(false);
					}
				).ConfigureAwait(false);
			}).ConfigureAwait(false);

			// special segments
			Base.AspNet.Global.StaticSegments.Append("statics");

			// handling unhandled exception
			AppDomain.CurrentDomain.UnhandledException += (sender, args) =>
			{
				Base.AspNet.Global.WriteDebugLogs(Base.AspNet.Global.GetCorrelationID(), Base.AspNet.Global.ServiceName, "An unhandled exception is thrown", args.ExceptionObject as Exception);
				Base.AspNet.Global.WriteLogs("An unhandled exception is thrown", args.ExceptionObject as Exception);
			};

			stopwatch.Stop();
			Task.Run(async () =>
			{
				await Task.Delay(345).ConfigureAwait(false);
				await Task.WhenAll(
					Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, $"*** The API Gateway HTTP Service is ready for serving. The app is initialized in {stopwatch.GetElapsedTimes()}"),
					Base.AspNet.Global.IsInfoLogEnabled ? Base.AspNet.Global.WriteLogsAsync(correlationID, $"*** The API Gateway HTTP Service is ready for serving. The app is initialized in {stopwatch.GetElapsedTimes()}") : Task.CompletedTask
				).ConfigureAwait(false);
			}).ConfigureAwait(false);
		}

		internal static void OnAppEnd()
		{
			Base.AspNet.Global.WriteDebugLogsAsync(UtilityService.NewUUID, Base.AspNet.Global.ServiceName, "Stop the API Gateway HTTP Service...");

			try
			{
				Global.InterCommunicateMessageUpdater?.Dispose();
			}
			catch { }

			RTU.Updaters.ForEach(updater =>
			{
				try
				{
					updater.Dispose();
				}
				catch { }
			});

			Base.AspNet.Global.CancellationTokenSource.Cancel();
			Base.AspNet.Global.CancellationTokenSource.Dispose();

			Base.AspNet.Global.CloseChannels();
			Base.AspNet.Global.RSA.Dispose();
		}
		#endregion

		#region Begin/End the request
		internal static void OnAppBeginRequest(HttpApplication app)
		{
			// update default headers to allow access from everywhere
			app.Context.Response.HeaderEncoding = Encoding.UTF8;
			app.Context.Response.Headers.Add("access-control-allow-origin", "*");
			app.Context.Response.Headers.Add("x-correlation-id", Base.AspNet.Global.GetCorrelationID(app.Context.Items));

			// prepare
			var executionFilePath = app.Request.AppRelativeCurrentExecutionFilePath;
			if (executionFilePath.StartsWith("~/"))
				executionFilePath = executionFilePath.Right(executionFilePath.Length - 2);

			var executionFilePaths = string.IsNullOrWhiteSpace(executionFilePath)
				? new[] {""}
				: executionFilePath.ToLower().ToArray('/', true);

			var correlationID = Base.AspNet.Global.GetCorrelationID(app.Context.Items);

			// update special headers on OPTIONS request
			if (app.Context.Request.HttpMethod.Equals("OPTIONS"))
			{
				app.Context.Response.Headers.Add("access-control-allow-methods", "GET,POST,PUT,DELETE");

				var allowHeaders = app.Context.Request.Headers.Get("access-control-request-headers");
				if (!string.IsNullOrWhiteSpace(allowHeaders))
					app.Context.Response.Headers.Add("access-control-allow-headers", allowHeaders);

				return;
			}

			// by-pass segments
			else if (Base.AspNet.Global.BypassSegments.Count > 0 && Base.AspNet.Global.BypassSegments.Contains(executionFilePaths[0]))
			{
				Base.AspNet.Global.WriteDebugLogs(correlationID, Base.AspNet.Global.ServiceName, $"Bypass the request of by-pass segment [{app.Context.Request.RawUrl}]");
				return;
			}

			// hidden segments
			else if (Base.AspNet.Global.HiddenSegments.Count > 0 && Base.AspNet.Global.HiddenSegments.Contains(executionFilePaths[0]))
			{
				Base.AspNet.Global.WriteDebugLogs(correlationID, Base.AspNet.Global.ServiceName, $"Stop the request of hidden segment [{app.Context.Request.RawUrl}]");
				Global.ShowError(app.Context, 403, "Forbidden", "AccessDeniedException", null, null);
				app.Context.Response.End();
				return;
			}

			// 403/404 errors
			else if (executionFilePaths[0].IsEquals("global.ashx"))
			{
				var errorElements = app.Context.Request.QueryString != null && app.Context.Request.QueryString.Count > 0
					? app.Context.Request.QueryString.ToString().UrlDecode().ToArray(';')
					: new string[] { "500", "" };
				var errorMessage = errorElements[0].Equals("403")
					? "Forbidden"
					: errorElements[0].Equals("404")
						? "Invalid"
						: "Unknown (" + errorElements[0] + " : " + (errorElements.Length > 1 ? errorElements[1].Replace(":80", "").Replace(":443", "") : "unknown") + ")";
				var errorType = errorElements[0].Equals("403")
					? "AccessDeniedException"
					: errorElements[0].Equals("404")
						? "InvalidRequestException"
						: "Unknown";						
				Global.ShowError(app.Context, errorElements[0].CastAs<int>(), errorMessage, errorType, null, null);
				app.Context.Response.End();
				return;
			}

			// track
			var appInfo = app.Context.GetAppInfo();
			var logs = new List<string>()
			{
				$"Begin of request [{app.Context.Request.HttpMethod}]: {app.Context.Request.Url.Scheme}://{app.Context.Request.Url.Host + app.Context.Request.RawUrl}",
				$"- Origin: {appInfo.Item1} / {appInfo.Item2} - {appInfo.Item3}",
				$"- IP: {app.Context.Request.UserHostAddress} [{app.Context.Request.UserAgent}]"
			};
			Base.AspNet.Global.WriteDebugLogs(correlationID, Base.AspNet.Global.ServiceName, logs);

			// diagnostics
			if (Base.AspNet.Global.IsInfoLogEnabled && !executionFilePaths[0].IsEquals("rtu"))
			{
				app.Context.Items["StopWatch"] = new Stopwatch();
				(app.Context.Items["StopWatch"] as Stopwatch).Start();
			}

			// rewrite url
			var url = app.Request.ApplicationPath + "Global.ashx?";
			if (Base.AspNet.Global.StaticSegments.Contains(executionFilePaths[0]))
				url += $"request-of-static-resource=&path={app.Context.Request.RawUrl.UrlEncode()}&";
			else
			{
				url += $"service-name={(!string.IsNullOrWhiteSpace(executionFilePaths[0]) ? executionFilePaths[0].GetANSIUri() : "")}&";
				if (executionFilePaths.Length > 1)
					url += $"object-name={executionFilePaths[1].GetANSIUri()}&";
				if (executionFilePaths.Length > 2)
					url += $"object-identity={executionFilePaths[2].GetANSIUri()}&";
			}

			foreach (string key in app.Request.QueryString)
				if (!string.IsNullOrWhiteSpace(key) && !Global.QueryExcluded.Contains(key))
					url += $"{key}={app.Request.QueryString[key].UrlEncode()}&";

			if (Base.AspNet.Global.IsInfoLogEnabled)
			{
				if (Base.AspNet.Global.IsDebugLogEnabled)
					logs.Add($"Rewrite URL: [{app.Context.Request.Url.Scheme}://{app.Context.Request.Url.Host + app.Context.Request.RawUrl}] => [{app.Context.Request.Url.Scheme}://{app.Context.Request.Url.Host + url.Left(url.Length - 1)}]");
				Base.AspNet.Global.WriteLogs(logs);
			}

			app.Context.RewritePath(url.Left(url.Length - 1));
		}

		internal static void OnAppEndRequest(HttpApplication app)
		{
			var executionTimes = "";
			if (Base.AspNet.Global.IsInfoLogEnabled && app.Context.Items.Contains("StopWatch"))
			{
				(app.Context.Items["StopWatch"] as Stopwatch).Stop();
				executionTimes = (app.Context.Items["StopWatch"] as Stopwatch).GetElapsedTimes();
				Base.AspNet.Global.WriteLogs($"End of request{(string.IsNullOrWhiteSpace(executionTimes) ? "" : " - Execution times: " + executionTimes)}");
				try
				{
					app.Response.Headers.Add("x-execution-times", executionTimes);
				}
				catch { }
			}
			Base.AspNet.Global.WriteDebugLogs(Base.AspNet.Global.GetCorrelationID(), Base.AspNet.Global.ServiceName, $"End of request{(string.IsNullOrWhiteSpace(executionTimes) ? "" : " - Execution times: " + executionTimes)}");
		}
		#endregion

		#region Pre excute handlers/send headers
		internal static void OnAppPreHandlerExecute(HttpApplication app)
		{
			// check
			if (app.Context.Request.HttpMethod.Equals("OPTIONS") || app.Context.Request.HttpMethod.Equals("HEAD"))
				return;

			// check
			var acceptEncoding = app.Context.Request.Headers["accept-encoding"];
			if (string.IsNullOrWhiteSpace(acceptEncoding))
				return;

			// apply compression
			var previousStream = app.Context.Response.Filter;

			// deflate
			if (acceptEncoding.IsContains("deflate") || acceptEncoding.Equals("*"))
			{
				app.Context.Response.Filter = new DeflateStream(previousStream, CompressionMode.Compress);
				app.Context.Response.Headers.Add("content-encoding", "deflate");
			}

			// gzip
			else if (acceptEncoding.IsContains("gzip"))
			{
				app.Context.Response.Filter = new GZipStream(previousStream, CompressionMode.Compress);
				app.Context.Response.Headers.Add("content-encoding", "gzip");
			}
		}

		internal static void OnAppPreSendHeaders(HttpApplication app)
		{
			// remove un-nessesary headers
			app.Context.Response.Headers.Remove("allow");
			app.Context.Response.Headers.Remove("public");
			app.Context.Response.Headers.Remove("x-powered-by");

			// add special headers
			if (app.Response.Headers["server"] != null)
				app.Response.Headers.Set("server", "VIEApps NGX");
			else
				app.Response.Headers.Add("server", "VIEApps NGX");
		}
		#endregion

		#region Error handlings
#if DEBUG
		static string ShowErrorStacks = "true";
#else
		static string ShowErrorStacks = null;
#endif

		internal static bool IsShowErrorStacks
		{
			get
			{
				return "true".IsEquals(Global.ShowErrorStacks ?? (Global.ShowErrorStacks = UtilityService.GetAppSetting("Errors:ShowStacks", "false")));
			}
		}

		internal static void ShowError(this HttpContext context, int code, string message, string type, string stack, Exception inner)
		{
			// prepare
			var isDangerous = message.Contains("potentially dangerous");
			var json = new JObject()
			{
				{ "Message", isDangerous ? "Invalid" : message },
				{ "Type", type },
				{ "Verb", context.Request.HttpMethod },
				{ "CorrelationID", Base.AspNet.Global.GetCorrelationID(context.Items) }
			};

			if (!string.IsNullOrWhiteSpace(stack) && Global.IsShowErrorStacks)
				json.Add(new JProperty("Stack", stack));

			if (inner != null && Global.IsShowErrorStacks)
			{
				var inners = new JArray();
				var counter = 0;
				var exception = inner;
				while (exception != null)
				{
					counter++;
					inners.Add(new JObject()
					{
						{ "Message", "(" + counter + "): " + exception.Message },
						{ "Type", exception.GetType().ToString() },
						{ "Stack", exception.StackTrace }
					});
					exception = exception.InnerException;
				}

				if (counter > 0)
					json.Add(new JProperty("Inners", inners));
			}

			// status code
			context.Response.TrySkipIisCustomErrors = true;
			context.Response.StatusCode = code < 1 ? 500 : code;

			// response bofy
			context.Response.Cache.SetNoStore();
			context.Response.ContentType = "application/json";
			context.Response.ClearContent();
			context.Response.Output.Write(json.ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None));

			// end response with dangerous requests
			if (isDangerous)
				context.Response.End();
		}

		internal static void ShowError(this HttpContext context, WampException exception, RequestInfo requestInfo = null, bool writeLogs = true)
		{
			// prepare
			var details = exception.GetDetails(requestInfo);
			var code = details.Item1;
			var message = details.Item2;
			var type = details.Item3;
			var stack = details.Item4;
			var inner = details.Item5;
			var jsonException = details.Item6;

			// show error
			context.ShowError(code, message, type, stack, inner);

			// write logs
			if (writeLogs)
			{
				var logs = new List<string>() { "[" + type + "]: " + message };

				stack = "";
				if (requestInfo != null)
					stack += "\r\n" + "==> Request:\r\n" + requestInfo.ToJson().ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None);

				if (jsonException != null)
					stack += "\r\n" + "==> Response:\r\n" + jsonException.ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None);

				if (exception != null)
				{
					stack += "\r\n" + "==> Stack:\r\n" + exception.StackTrace;
					var counter = 0;
					var innerException = exception.InnerException;
					while (innerException != null)
					{
						counter++;
						stack += "\r\n" + $"-------- Inner ({counter}) ----------------------------------"
							+ "> Message: " + innerException.Message + "\r\n"
							+ "> Type: " + innerException.GetType().ToString() + "\r\n"
							+ innerException.StackTrace;
						innerException = innerException.InnerException;
					}
				}

				Base.AspNet.Global.WriteLogs(requestInfo?.CorrelationID ?? Base.AspNet.Global.GetCorrelationID(context.Items), requestInfo?.ObjectName ?? "unknown", logs, stack, requestInfo?.ServiceName ?? "unknown");
			}
		}

		internal static void ShowError(this HttpContext context, Exception exception, RequestInfo requestInfo = null, bool writeLogs = true)
		{
			// write logs
			if (writeLogs && exception != null)
				Base.AspNet.Global.WriteLogs(Base.AspNet.Global.GetCorrelationID(context.Items), "Internal", $"Error occurred while processing (Request: {requestInfo?.ToJson().ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None) ?? "None"})", exception);

			// show error
			if (exception is WampException)
				context.ShowError(exception as WampException, requestInfo, writeLogs);

			else
			{
				var message = exception != null ? exception.Message : "Unknown error";
				var type = exception != null ? exception.GetType().ToString().ToArray('.').Last() : "Unknown";
				var stack = exception != null && Global.IsShowErrorStacks ? exception.StackTrace : null;
				var inner = exception != null && Global.IsShowErrorStacks ? exception.InnerException : null;
				context.ShowError(exception != null ? exception.GetHttpStatusCode() : 500, message, type, stack, inner);
			}
		}

		internal static void OnAppError(HttpApplication app)
		{
			var exception = app.Server.GetLastError();
			app.Server.ClearError();
			app.Context.ShowError(exception, null, true);
			Base.AspNet.Global.WriteDebugLogs(Base.AspNet.Global.GetCorrelationID(app.Context.Items), Base.AspNet.Global.ServiceName, "Got an unhandled error exception while processing", exception);
		}
		#endregion

		#region User tokens
		internal static string GetAccessToken(this User user)
		{
			return User.GetAccessToken(user, Base.AspNet.Global.RSA, Base.AspNet.Global.EncryptionKey);
		}

		internal static string GetJSONWebToken(this Session session, string accessToken = null)
		{
			return User.GetJSONWebToken(
				session.User.ID,
				accessToken ?? session.User.GetAccessToken(),
				session.SessionID,
				Base.AspNet.Global.EncryptionKey,
				Base.AspNet.Global.JWTKey,
				(payload) =>
				{
					payload.Add(new JProperty("j2f", $"{session.Verification.ToString()}|{UtilityService.NewUUID}".Encrypt(Base.AspNet.Global.EncryptionKey)));
				}
			);
		}

		internal static string ParseJSONWebToken(this Session session, string jwt)
		{
			// parse JSON Web Token
			var userID = "";
			var accessToken = "";
			var sessionID = "";
			try
			{
				var info = User.ParseJSONWebToken(jwt, Base.AspNet.Global.EncryptionKey, Base.AspNet.Global.JWTKey, (payload) =>
				{
					try
					{
						session.Verification = "true".IsEquals((payload["j2f"] as JValue).Value.ToString().Decrypt(Base.AspNet.Global.EncryptionKey).ToArray("|").First());
					}
					catch { }
				});
				userID = info.Item1;
				accessToken = info.Item2;
				sessionID = info.Item3;
			}
			catch (Exception)
			{
				throw;
			}

			// get user information
			try
			{
				session.User = User.ParseAccessToken(accessToken, Base.AspNet.Global.RSA, Base.AspNet.Global.EncryptionKey);
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Token is invalid (Access token is invalid)", ex);
			}

			if (!session.User.ID.Equals(userID))
				throw new InvalidTokenException("Token is invalid (User identity is invalid)");

			// assign identity of the session
			session.SessionID = sessionID;

			// return access token
			return accessToken;
		}
		#endregion

		#region Send & process inter-communicate message
		internal static async Task SendInterCommunicateMessageAsync(CommunicateMessage message)
		{
			var correlationID = Base.AspNet.Global.GetCorrelationID();
			try
			{
				await Base.AspNet.Global.RTUService.SendInterCommunicateMessageAsync(message, Base.AspNet.Global.CancellationTokenSource.Token).ConfigureAwait(false);
				await Task.WhenAll(
					Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, $"Send an inter-communicate message successful\r\n{message.ToJson().ToString(Base.AspNet.Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"),
					Base.AspNet.Global.IsDebugLogEnabled ? Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", $"Send an inter-communicate message successful\r\n{message.ToJson().ToString(Formatting.Indented)}") : Task.CompletedTask
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await Task.WhenAll(
					Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, "Error occurred while sending an inter-communicate message", ex),
					Base.AspNet.Global.WriteLogsAsync(correlationID, "RTU", "Error occurred while sending an inter-communicate message", ex)
				).ConfigureAwait(false);
			}
		}

		static async Task ProcessInterCommunicateMessageAsync(CommunicateMessage message)
		{
			// update users' sessions with new access token
			if (message.Type.Equals("Session#Update"))
			{
				var sessionID = (message.Data["Session"] as JValue).Value as string;
				var user = (message.Data["User"] as JObject).FromJson<User>();
				var deviceID = (message.Data["Device"] as JValue).Value as string;
				var verification = (message.Data["Verification"] as JValue).Value.CastAs<bool>();
				var accessToken = ((message.Data["Token"] as JValue).Value as string).Decrypt(Base.AspNet.Global.EncryptionKey);

				await Global.Cache.RemoveAsync("Session#" + sessionID).ConfigureAwait(false);

				var json = new JObject()
				{
					{ "ID", sessionID },
					{ "UserID", user.ID },
					{ "DeviceID", deviceID },
					{ "Mode", "Update" }
				};

				new Session()
				{
					SessionID = sessionID,
					DeviceID = deviceID,
					User = user,
					Verification = verification
				}.UpdateSessionJson(json, accessToken);

				await new UpdateMessage()
				{
					Type = "Users#Session",
					DeviceID = deviceID,
					Data = json
				}.PublishAsync().ConfigureAwait(false);
			}

			// revoke users' sessions
			else if (message.Type.Equals("Session#Revoke"))
			{
				var sessionID = (message.Data["Session"] as JValue).Value as string;
				var user = (message.Data["User"] as JObject).FromJson<User>();
				var deviceID = (message.Data["Device"] as JValue).Value as string;

				var json = new JObject()
				{
					{ "ID", sessionID },
					{ "UserID", user.ID },
					{ "DeviceID", deviceID },
					{ "Mode", "Revoke" }
				};

				new Session()
				{
					SessionID = sessionID,
					DeviceID = deviceID,
					User = user
				}.UpdateSessionJson(json, null);

				await new UpdateMessage()
				{
					Type = "Users#Session",
					DeviceID = deviceID,
					Data = json
				}.PublishAsync().ConfigureAwait(false);
			}

			// refresh users' sessions (clear cached)
			else if (message.Type.Equals("Session#Refresh"))
				await Global.Cache.RemoveAsync($"Session#{(message.Data["Session"] as JValue).Value as string}").ConfigureAwait(false);
		}

		internal static async Task PublishAsync(this UpdateMessage message)
		{
			if (Global.UpdateMessagePublisher == null)
				try
				{
					await Base.AspNet.Global.OpenOutgoingChannelAsync().ConfigureAwait(false);
					Global.UpdateMessagePublisher = Base.AspNet.Global.OutgoingChannel.RealmProxy.Services.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages");
					Global.UpdateMessagePublisher.OnNext(message);
				}
				catch (Exception ex)
				{
					await Task.WhenAll(
						Base.AspNet.Global.WriteDebugLogsAsync(Base.AspNet.Global.GetCorrelationID(), Base.AspNet.Global.ServiceName, $"Error occurred while publishing an update message: {message.ToJson().ToString(Base.AspNet.Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}", ex),
						Base.AspNet.Global.WriteLogsAsync(Base.AspNet.Global.GetCorrelationID(), "RTU", $"Error occurred while publishing an update message: {message.ToJson().ToString(Formatting.Indented)}", ex)
					).ConfigureAwait(false);
				}

			else
				try
				{
					Global.UpdateMessagePublisher.OnNext(message);
				}
				catch (Exception ex)
				{
					await Task.WhenAll(
						Base.AspNet.Global.WriteDebugLogsAsync(Base.AspNet.Global.GetCorrelationID(), Base.AspNet.Global.ServiceName, $"Error occurred while publishing an update message: {message.ToJson().ToString(Base.AspNet.Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}", ex),
						Base.AspNet.Global.WriteLogsAsync(Base.AspNet.Global.GetCorrelationID(), "RTU", $"Error occurred while publishing an update message: {message.ToJson().ToString(Formatting.Indented)}", ex)
					).ConfigureAwait(false);
				}
		}
		#endregion

	}

	// ------------------------------------------------------------------------------

	#region Global.ashx
	public class GlobalHandler : HttpTaskAsyncHandler
	{
		public GlobalHandler() : base() { }

		public override async Task ProcessRequestAsync(HttpContext context)
		{
			var correlationID = Base.AspNet.Global.GetCorrelationID(context.Items);

			// stop process request is OPTIONS
			if (context.Request.HttpMethod.Equals("OPTIONS"))
				return;

			// real-time update
			if (context.IsWebSocketRequest)
				context.AcceptWebSocketRequest(RTU.ProcessRequestAsync);

			// static resources
			else if (context.Request.QueryString["request-of-static-resource"] != null)
			{
				// check "If-Modified-Since" request to reduce traffict
				var eTag = "StaticResource#" + context.Request.RawUrl.ToLower().GetMD5();
				if (context.Request.Headers["If-Modified-Since"] != null && eTag.Equals(context.Request.Headers["If-None-Match"]))
				{
					context.Response.Cache.SetCacheability(HttpCacheability.Public);
					context.Response.StatusCode = (int)HttpStatusCode.NotModified;
					context.Response.StatusDescription = "Not Modified";
					context.Response.Headers.Add("ETag", "\"" + eTag + "\"");
					return;
				}

				// prepare
				var path = context.Request.QueryString["path"];
				if (string.IsNullOrWhiteSpace(path))
					path = "~/data-files/statics/geo/countries.json";

				if (path.IndexOf("?") > 0)
					path = path.Left(path.IndexOf("?"));

				// process
				try
				{
					// get information of the requested file
					var filePath = "";
					if (!path.IsStartsWith("/statics/"))
						filePath = context.Server.MapPath(path);

					else
					{
						filePath = UtilityService.GetAppSetting("Path:StaticFiles");
						if (string.IsNullOrEmpty(filePath))
							filePath = HttpRuntime.AppDomainAppPath + @"\data-files\statics";
						if (filePath.EndsWith(@"\"))
							filePath = filePath.Left(filePath.Length - 1);

						filePath += path.Replace("/statics/", "/").Replace("/", @"\");
					}

					// check exist
					var fileInfo = new FileInfo(filePath);
					if (!fileInfo.Exists)
						throw new FileNotFoundException();

					// set cache policy
					context.Response.Cache.SetCacheability(HttpCacheability.Public);
					context.Response.Cache.SetExpires(DateTime.Now.AddDays(1));
					context.Response.Cache.SetSlidingExpiration(true);
					context.Response.Cache.SetOmitVaryStar(true);
					context.Response.Cache.SetValidUntilExpires(true);
					context.Response.Cache.SetLastModified(fileInfo.LastWriteTime);
					context.Response.Cache.SetETag(eTag);

					// prepare content
					var staticMimeType = MimeMapping.GetMimeMapping(fileInfo.Name);
					if (string.IsNullOrWhiteSpace(staticMimeType))
						staticMimeType = "text/plain";

					var staticContent = await UtilityService.ReadTextFileAsync(fileInfo).ConfigureAwait(false);
					if (staticMimeType.IsEndsWith("json"))
						staticContent = JObject.Parse(staticContent).ToString(Formatting.Indented);

					// write content
					context.Response.ContentType = staticMimeType;
					await Task.WhenAll(
						context.Response.Output.WriteAsync(staticContent),
						Base.AspNet.Global.WriteDebugLogsAsync(correlationID, Base.AspNet.Global.ServiceName, $"Process request of static file successful [{path}]")
					).ConfigureAwait(false);
				}
				catch (FileNotFoundException ex)
				{
					Base.AspNet.Global.WriteDebugLogs(correlationID, Base.AspNet.Global.ServiceName, $"Static file is not found [{path}]", ex);
					context.ShowError((int)HttpStatusCode.NotFound, $"Not found [{path}]", "FileNotFoundException", ex.StackTrace, ex.InnerException);
				}
				catch (Exception ex)
				{
					Base.AspNet.Global.WriteDebugLogs(correlationID, Base.AspNet.Global.ServiceName, $"Error occurred while processing static file [{path}]", ex);
					context.ShowError(ex);
				}
			}

			// APIs
			else
			{
				// prepare
				var serviceName = context.Request.QueryString["service-name"];

				// no information
				if (string.IsNullOrWhiteSpace(serviceName))
				{
					Base.AspNet.Global.WriteDebugLogs(correlationID, Base.AspNet.Global.ServiceName, $"The request is invalid [{context.Request.RawUrl}]");
					context.ShowError(new InvalidRequestException());
				}

				// external APIs
				else if (ExternalAPIs.APIs.ContainsKey(serviceName))
					await ExternalAPIs.ProcessRequestAsync(context).ConfigureAwait(false);

				// internal APIs
				else
					await InternalAPIs.ProcessRequestAsync(context).ConfigureAwait(false);
			}
		}
	}
	#endregion

	#region Global.asax
	public class GlobalApp : HttpApplication
	{

		protected void Application_Start(object sender, EventArgs args)
		{
			Global.OnAppStart(sender as HttpContext);
		}

		protected void Application_BeginRequest(object sender, EventArgs args)
		{
			Global.OnAppBeginRequest(sender as HttpApplication);
		}

		protected void Application_PreRequestHandlerExecute(object sender, EventArgs args)
		{
			Global.OnAppPreHandlerExecute(sender as HttpApplication);
		}

		protected void Application_PreSendRequestHeaders(object sender, EventArgs args)
		{
			Global.OnAppPreSendHeaders(sender as HttpApplication);
		}

		protected void Application_EndRequest(object sender, EventArgs args)
		{
			Global.OnAppEndRequest(sender as HttpApplication);
		}

		protected void Application_Error(object sender, EventArgs args)
		{
			Global.OnAppError(sender as HttpApplication);
		}

		protected void Application_End(object sender, EventArgs args)
		{
			Global.OnAppEnd();
		}
	}
	#endregion

}