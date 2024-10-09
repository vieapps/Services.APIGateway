#region Related components
using System;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Dynamic;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using WampSharp.V2.Core.Contracts;
using net.vieapps.Components.Security;
using net.vieapps.Components.WebSockets;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class WebSocketAPIs
	{
		static Components.WebSockets.WebSocket WebSocket { get; set; }

		public static ILogger Logger { get; set; }

		public static TimeSpan KeepAliveInterval => WebSocketAPIs.WebSocket.KeepAliveInterval;

		public static void Initialize()
		{
			WebSocketAPIs.WebSocket = new Components.WebSockets.WebSocket(Components.Utility.Logger.GetLoggerFactory(), Global.CancellationToken)
			{
				OnError = async (websocket, exception) => await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs", $"Got an error while processing => {exception.Message} ({websocket?.ID} {websocket?.RemoteEndPoint})", exception).ConfigureAwait(false),
				OnConnectionEstablished = async websocket => await (websocket == null ? Task.CompletedTask : websocket.WhenConnectionIsEstablishedAsync()).ConfigureAwait(false),
				OnConnectionBroken = async websocket => await (websocket == null ? Task.CompletedTask : websocket.WhenConnectionIsBrokenAsync()).ConfigureAwait(false),
				OnMessageReceived = async (websocket, result, data) => await (websocket == null ? Task.CompletedTask : websocket.WhenMessageIsReceivedAsync(result, data)).ConfigureAwait(false),
				KeepAliveInterval = TimeSpan.FromSeconds(Int32.TryParse(UtilityService.GetAppSetting("Proxy:KeepAliveInterval", "45"), out var interval) ? interval : 45)
			};
			Global.Logger.LogInformation($"{Global.ServiceName} WebSocket APIs was initialized - Buffer size: {Components.WebSockets.WebSocket.ReceiveBufferSize:#,##0} bytes - Keep-Alive interval: {WebSocketAPIs.WebSocket.KeepAliveInterval.TotalSeconds} second(s)");
		}

		public static void Dispose()
		{
			WebSocketAPIs.WebSocket.Dispose();
			Global.Logger.LogInformation($"The WebSocket APIs was disposed");
		}

		public static Task WrapWebSocketAsync(HttpContext context, Func<HttpContext, Task> whenIsNotWebSocketRequestAsync = null)
			=> WebSocketAPIs.WebSocket.WrapAsync(context, whenIsNotWebSocketRequestAsync);

		public static async Task BroadcastAsync(UpdateMessage message)
		{
			try
			{
				await WebSocketAPIs.WebSocket.SendAsync(websocket =>
				{
					if ("Disconnected".IsEquals(websocket.GetStatus()))
						return false;

					var session = websocket.Get<Session>("Session");
					if (session == null || session.DeviceID.IsEquals(message.ExcludedDeviceID) || (!"*".Equals(message.DeviceID) && !session.DeviceID.IsEquals(message.DeviceID)))
						return false;

					return true;
				}, message.ToJson().ToString(Formatting.None).ToBytes(), true, Global.CancellationToken).ConfigureAwait(false);
				if (Global.IsDebugLogEnabled)
					await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs",
						$"Successfully broadcast a message to all connected devices" + "\r\n" +
						$"- Type: {message.Type}" + "\r\n" +
						$"- Message: {message.Data?.ToString(RESTfulAPIs.JsonFormat)}"
					, null, Global.ServiceName, LogLevel.Debug).ConfigureAwait(false);
			}
			catch (OperationCanceledException) { }
			catch (ObjectDisposedException) { }
			catch (Exception ex)
			{
				await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs",
					$"Error occurred while broadcasting a message to all connected devices => {ex.Message}" + "\r\n" +
					$"- Type: {message.Type}" + "\r\n" +
					$"- Message: {message.ToJson().ToString(RESTfulAPIs.JsonFormat)}"
				, ex, Global.ServiceName, LogLevel.Error).ConfigureAwait(false);
			}
		}

		static async Task WhenConnectionIsEstablishedAsync(this ManagedWebSocket websocket)
		{
			// update status
			websocket.SetStatus("Initializing");
			var correlationID = UtilityService.NewUUID;

			// prepare session
			try
			{
				var query = websocket.RequestUri.ParseQuery();
				var session = Global.GetSession(websocket.Headers, query, $"{(websocket.RemoteEndPoint as IPEndPoint).Address}");

				// update session identity
				session.SessionID = query.TryGetValue("x-session-id", out var sessionID) ? sessionID.Url64Decode() : "";
				if (string.IsNullOrWhiteSpace(session.SessionID))
					throw new InvalidRequestException("Session identity is not found");

				// update device identity
				session.DeviceID = query.TryGetValue("x-device-id", out var deviceID) ? deviceID.Url64Decode() : "";
				if (string.IsNullOrWhiteSpace(session.DeviceID))
					throw new InvalidRequestException("Device identity is not found");

				// update session
				websocket.Set("Session", session);
				await websocket.PrepareConnectionInfoAsync(correlationID, session, Global.CancellationToken, WebSocketAPIs.Logger).ConfigureAwait(false);

				// wait for few times before connecting to API Gateway Router because RxNET needs that
				if (query.ContainsKey("x-restart"))
					await Task.WhenAll
					(
						websocket.SendAsync(new UpdateMessage { Type = "Knock" }),
						Task.Delay(345, Global.CancellationToken)
					).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await WebSocketAPIs.WebSocket.CloseWebSocketAsync(websocket, ex is InvalidRequestException ? WebSocketCloseStatus.InvalidPayloadData : WebSocketCloseStatus.InternalServerError, ex is InvalidRequestException ? $"Request is invalid => {ex.Message}" : ex.Message).ConfigureAwait(false);
				return;
			}

			// subscribe an updater to push messages to client device
			websocket.Set("Updater", Services.Router.IncomingChannel.RealmProxy.Services
				.GetSubject<UpdateMessage>("messages.update")
				.Subscribe
				(
					async message => await websocket.PushAsync(message).ConfigureAwait(false),
					async exception => await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs", $"Error occurred while fetching an updating message => {exception.Message}", exception).ConfigureAwait(false)
				)
			);

			// subscribe a communicator to update related information
			websocket.Set("Communicator", Services.Router.IncomingChannel.RealmProxy.Services
				.GetSubject<CommunicateMessage>("messages.services.apigateway")
				.Subscribe
				(
					async message => await websocket.CommunicateAsync(message).ConfigureAwait(false),
					async exception => await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs", $"Error occurred while fetching an inter-communicating message => {exception.Message}", exception).ConfigureAwait(false)
				)
			);

			// update status
			websocket.SetStatus("Connected");
			if (Global.IsVisitLogEnabled)
				await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.Visits", $"The connection of the WebSocket APIs was established" + "\r\n" + websocket.GetConnectionInfo() + "\r\n" + $"- Status: {websocket.GetStatus()}", null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);
		}

		static async Task WhenConnectionIsBrokenAsync(this ManagedWebSocket websocket)
		{
			// prepare
			websocket.SetStatus("Disconnected");
			websocket.Remove("Session", out Session session);
			var correlationID = UtilityService.NewUUID;

			// remove the updater
			if (websocket.Remove("Updater", out IDisposable updater))
				try
				{
					updater?.Dispose();
				}
				catch (Exception ex)
				{
					await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs", $"Error occurred while disposing updater: {session?.ToJson()?.ToString(Global.IsDebugResultsEnabled ? Formatting.Indented : Formatting.None)}", ex, Global.ServiceName, LogLevel.Error, correlationID).ConfigureAwait(false);
				}

			// remove the communicator
			if (websocket.Remove("Communicator", out IDisposable communicator))
				try
				{
					communicator?.Dispose();
				}
				catch (Exception ex)
				{
					await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs", $"Error occurred while disposing communicator: {session?.ToJson()?.ToString(Global.IsDebugResultsEnabled ? Formatting.Indented : Formatting.None)}", ex, Global.ServiceName, LogLevel.Error, correlationID).ConfigureAwait(false);
				}

			// update the session state
			await Task.WhenAll
			(
				session != null ? session.SendSessionStateAsync(false, correlationID) : Task.CompletedTask,
				Global.IsVisitLogEnabled ? Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.Visits", $"The connection of the WebSocket APIs was stopped" + "\r\n" + websocket.GetConnectionInfo(session) + "\r\n" + $"- Served times: {websocket.Timestamp.GetElapsedTimes()}", null, Global.ServiceName, LogLevel.Information, correlationID) : Task.CompletedTask
			).ConfigureAwait(false);
		}

		static async Task WhenMessageIsReceivedAsync(this ManagedWebSocket websocket, WebSocketReceiveResult result, byte[] data)
		{
			// receive continuous messages
			object message;
			if (!result.EndOfMessage)
			{
				websocket.Extra["Message"] = websocket.Extra.TryGetValue("Message", out message) ? (message as byte[]).Concat(data) : data;
				return;
			}

			// last message or single small message
			var stopwatch = Stopwatch.StartNew();
			var correlationID = UtilityService.NewUUID;

			if (websocket.Extra.TryGetValue("Message", out message))
			{
				message = (message as byte[]).Concat(data);
				websocket.Extra.Remove("Message");
			}
			else
				message = data;

			// check message
			var requestMsg = result.MessageType.Equals(WebSocketMessageType.Text) ? (message as byte[]).GetString() : null;
			if (string.IsNullOrWhiteSpace(requestMsg))
				return;

			// wait for the initializing process is completed
			while ("Initializing".IsEquals(websocket.GetStatus()))
				await Task.Delay(UtilityService.GetRandomNumber(123, 456), Global.CancellationToken).ConfigureAwait(false);

			// check session
			var session = websocket.Get<Session>("Session");
			if (session == null)
			{
				await Task.WhenAll
				(
					Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs", $"No session is attached - Request: {requestMsg}", null, Global.ServiceName, LogLevel.Critical, correlationID),
					WebSocketAPIs.WebSocket.CloseWebSocketAsync(websocket, WebSocketCloseStatus.PolicyViolation, "No session")
				).ConfigureAwait(false);
				return;
			}

			// prepare
			var requestObj = requestMsg.ToExpandoObject();
			var serviceName = requestObj.Get("ServiceName", "").GetCapitalizedFirstLetter();
			var objectName = requestObj.Get("ObjectName", "").GetCapitalizedFirstLetter();
			var verb = requestObj.Get("Verb", "GET").ToUpper();
			var query = new Dictionary<string, string>(requestObj.Get("Query", new Dictionary<string, string>()), StringComparer.OrdinalIgnoreCase);
			query.TryGetValue("object-identity", out var objectIdentity);

			// visit logs
			if (Global.IsVisitLogEnabled)
				await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.Visits",
					$"Request starting {verb} " + $"/{serviceName.ToLower()}{(string.IsNullOrWhiteSpace(objectName) ? "" : $"/{objectName.ToLower()}")}{(string.IsNullOrWhiteSpace(objectIdentity) ? "" : $"/{objectIdentity}")}".ToLower() + (query.TryGetValue("x-request", out var xrequest) ? $"?x-request={xrequest}" : "") + " HTTPWS/1.1" + " \r\n" +
					$"- App: {session.AppName ?? "Unknown"} @ {session.AppPlatform ?? "Unknown"} [{session.AppAgent ?? "Unknown"}]" + " \r\n" +
					$"- WebSocket: {websocket.ID} @ {websocket.RemoteEndPoint}"
				, null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);

			// process requests of a session
			if ("session".IsEquals(serviceName))
				await websocket.ProcessSessionAsync(requestObj, session, correlationID).ConfigureAwait(false);

			// process requests of a service
			else
			{
				// wait for the authenticating process in 5 seconds
				if (!"Authenticated".IsEquals(websocket.GetStatus()))
					using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
					{
						while (!cts.IsCancellationRequested)
							try
							{
								await Task.Delay(UtilityService.GetRandomNumber(123, 456), Global.CancellationToken).ConfigureAwait(false);
								if ("Authenticated".IsEquals(websocket.GetStatus()))
									cts.Cancel();
							}
							catch { }
					}

				// process the request
				if ("Authenticated".IsEquals(websocket.GetStatus()))
					await websocket.ProcessRequestAsync(requestObj, session, correlationID).ConfigureAwait(false);
				else
					await Task.WhenAll
					(
						Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs",
							$"Session is not authenticated" + "\r\n" +
							$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
							$"- Status: {websocket.GetStatus()}"
						, null, Global.ServiceName, LogLevel.Critical, correlationID),
						WebSocketAPIs.WebSocket.CloseWebSocketAsync(websocket, WebSocketCloseStatus.PolicyViolation, "Need to authenticate the session")
					).ConfigureAwait(false);
			}

			// visit logs
			stopwatch.Stop();
			if (Global.IsVisitLogEnabled)
				await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.Visits", $"Request finished in {stopwatch.GetElapsedTimes()}", null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);
		}

		static void SetStatus(this ManagedWebSocket websocket, string status)
			=> websocket.Set("Status", status);

		static string GetStatus(this ManagedWebSocket websocket)
			=> websocket.Get<string>("Status");

		static async Task SendAsync(this ManagedWebSocket websocket, Exception exception, string correlationID = null, string identity = null, string additionalMsg = null)
		{
			correlationID = correlationID ?? UtilityService.NewUUID;
			try
			{
				// prepare
				var wampDetails = exception != null && exception is WampException
					? (exception as WampException).GetDetails()
					: null;

				var msg = wampDetails?.Item2 ?? exception.Message ?? "Unknown error";
				var type = wampDetails?.Item3 ?? exception?.GetType().GetTypeName(true) ?? "UnknownException";
				var code = wampDetails != null ? wampDetails.Item1 : exception != null ? exception.GetHttpStatusCode() : 500;

				var message = new JObject
				{
					{ "Message", msg },
					{ "Type", type },
					{ "Code", code }
				};

				if (Global.IsDebugStacksEnabled)
				{
					if (wampDetails != null)
					{
						var stacks = new JArray { wampDetails.Item4 };
						var inner = wampDetails.Item6;
						while (inner != null)
						{
							stacks.Add($"{inner.Get<string>("Message")} [{inner.Get<string>("Type")}] {inner.Get<string>("StackTrace")}");
							inner = inner.Get<JObject>("InnerException");
						}
						message["StackTrace"] = stacks;
					}

					else
						message["StackTrace"] = exception?.GetStacks();
				}

				message["CorrelationID"] = correlationID;
				message = new JObject
				{
					{ "Type", "Error" },
					{ "Data", message }
				};
				if (!string.IsNullOrWhiteSpace(identity))
					message["ID"] = identity;

				// send & write logs
				await websocket.SendAsync(message, Global.CancellationToken).ConfigureAwait(false);
				await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs", msg ?? exception.Message, exception, Global.ServiceName, LogLevel.Error, correlationID, string.IsNullOrWhiteSpace(additionalMsg) ? null : $"{additionalMsg}\r\nWebSocket Info:\r\n{websocket.GetConnectionInfo()}").ConfigureAwait(false);
			}
			catch (ObjectDisposedException) { }
			catch (Exception ex)
			{
				WebSocketAPIs.Logger.LogError($"Error occurred while sending an error message via WebSocket => {ex.Message}", ex);
			}
		}

		static Task SendAsync(this ManagedWebSocket websocket, UpdateMessage message, string identity = null, string correlationID = null)
			=> websocket.SendAsync(message, Global.CancellationToken, json =>
			{
				(json as JObject).Remove("DeviceID");
				(json as JObject).Remove("ExcludedDeviceID");
				if (!string.IsNullOrWhiteSpace(identity))
					json["ID"] = identity;
				if (!string.IsNullOrWhiteSpace(correlationID))
					json["CorrelationID"] = correlationID;
			});

		static async Task PushAsync(this ManagedWebSocket websocket, UpdateMessage message)
		{
			if ("Disconnected".IsEquals(websocket.GetStatus()))
				return;

			var session = websocket.Get<Session>("Session");
			if (session == null || session.DeviceID.IsEquals(message.ExcludedDeviceID) || (!"*".Equals(message.DeviceID) && !session.DeviceID.IsEquals(message.DeviceID)))
				return;

			try
			{
				await websocket.SendAsync(message).ConfigureAwait(false);
				if (Global.IsDebugLogEnabled)
					await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs",
						$"Successfully push a message to the device ({message?.DeviceID})" + "\r\n" +
						$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
						$"- Type: {message.Type}" + "\r\n" +
						$"- Message: {message.Data?.ToString(RESTfulAPIs.JsonFormat)}"
					, null, Global.ServiceName, LogLevel.Information).ConfigureAwait(false);
			}
			catch (ObjectDisposedException) { }
			catch (Exception ex)
			{
				await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs",
					$"Error occurred while pushing a message to the device ({message?.DeviceID}) => {ex.Message}" + "\r\n" +
					$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
					$"- Type: {message.Type}" + "\r\n" +
					$"- Message: {message.ToJson().ToString(RESTfulAPIs.JsonFormat)}"
				, ex, Global.ServiceName, LogLevel.Error).ConfigureAwait(false);
			}
		}

		static async Task CommunicateAsync(this ManagedWebSocket websocket, CommunicateMessage message)
		{
			if ("Disconnected".IsEquals(websocket.GetStatus()))
				return;

			var session = websocket.Get<Session>("Session");
			if (session == null || !session.SessionID.IsEquals(message.Data.Get<string>("SessionID")))
				return;

			var correlationID = UtilityService.NewUUID;
			try
			{
				// patch the session (update session with new identity and privileges)
				if (message.Type.IsEquals("Session#Patch"))
				{
					var authenticateToken = message.Data.Get<string>("AuthenticateToken");
					var encryptedSessionID = message.Data.Get<string>("EncryptedID");
					await Global.UpdateWithAuthenticateTokenAsync(session, authenticateToken, 0, null, null, null, WebSocketAPIs.Logger, "Http.APIs", correlationID).ConfigureAwait(false);
					if (!await session.IsSessionExistAsync(WebSocketAPIs.Logger, "Http.APIs", correlationID).ConfigureAwait(false))
						throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
					else if (!session.SessionID.Equals(session.GetDecryptedID(encryptedSessionID, Global.EncryptionKey, Global.ValidationKey)))
						throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
					await websocket.PrepareConnectionInfoAsync(correlationID, session, Global.CancellationToken, WebSocketAPIs.Logger).ConfigureAwait(false);
					if (Global.IsDebugLogEnabled)
						await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs",
							$"Successfully process an inter-communicate message (patch session - {message.Data.Get<string>("SessionID")} => {session.SessionID})" + "\r\n" +
							$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
							$"- Type: {message.Type}" + "\r\n" +
							$"- Message: {message.Data.ToString(Formatting.None)}"
						, null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);
				}

				// update the session with new users' privileges => new access token
				else if (message.Type.IsEquals("Session#Update"))
				{
					session.User = message.Data.Get<JObject>("User")?.Copy<User>() ?? session.User;
					session.Verified = message.Data.Get<bool>("Verified");
					await websocket.SendAsync(new UpdateMessage
					{
						Type = "Users#Session#Update",
						Data = session.GetSessionJson()
					}).ConfigureAwait(false);
					if (Global.IsDebugLogEnabled)
						await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs",
							$"Successfully process an inter-communicate message (update session)" + "\r\n" +
							$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
							$"- Type: {message.Type}" + "\r\n" +
							$"- Message: {message.Data.ToString(Formatting.None)}"
						, null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);
				}

				// revoke a session => tell client to log-out and register new session
				else if (message.Type.IsEquals("Session#Revoke"))
				{
					await session.SendSessionStateAsync(false, correlationID).ConfigureAwait(false);
					session.SessionID = UtilityService.NewUUID;
					session.User = new User("", session.SessionID, new List<string> { SystemRole.All.ToString() }, new List<Privilege>());
					session.Verified = false;
					await Task.WhenAll
					(
						Global.Cache.SetAsync($"Session#{session.SessionID}", session.GetEncryptedID(), 13),
						websocket.SendAsync(new UpdateMessage
						{
							Type = "Users#Session#Revoke",
							Data = session.GetSessionJson()
						})
					).ConfigureAwait(false);
					if (Global.IsDebugLogEnabled)
						await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs",
							$"Successfully process an inter-communicate message (revoke session)" + "\r\n" +
							$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
							$"- Type: {message.Type}" + "\r\n" +
							$"- Message: {message.Data.ToString(Formatting.None)}"
						, null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);
				}
			}
			catch (ObjectDisposedException) { }
			catch (Exception ex)
			{
				await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs",
					$"Error occurred while processing an inter-communicate message => {ex.Message}" + "\r\n" +
					$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
					$"- Type: {message.Type}" + "\r\n" +
					$"- Message: {message.ToJson().ToString(RESTfulAPIs.JsonFormat)}"
				, ex, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);
			}
		}

		static async Task ProcessSessionAsync(this ManagedWebSocket websocket, ExpandoObject requestObj, Session session = null, string correlationID = null)
		{
			session = session ?? websocket.Get<Session>("Session");
			correlationID = correlationID ?? UtilityService.NewUUID;
			try
			{
				// authenticate the session
				var verb = requestObj.Get("Verb", "GET").ToUpper();
				if ("AUTH".IsEquals(verb) || "VERIFY".IsEquals(verb) || "HEAD".IsEquals(verb) || "PATCH".IsEquals(verb))
				{
					// update status
					websocket.SetStatus("Authenticating");

					// authenticate
					var body = requestObj.Get("Body")?.ToExpandoObject();
					var appToken = body?.Get<string>("x-app-token") ?? "";
					await Global.UpdateWithAuthenticateTokenAsync(session, appToken, RESTfulAPIs.ExpiresAfter, null, null, null, WebSocketAPIs.Logger, "Http.APIs", correlationID).ConfigureAwait(false);
					if (!await session.IsSessionExistAsync(WebSocketAPIs.Logger, "Http.APIs", correlationID).ConfigureAwait(false))
						throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");

					// verify identity of session and device
					var header = new Dictionary<string, string>(requestObj.Get("Header", new Dictionary<string, string>()), StringComparer.OrdinalIgnoreCase);
					var encryptionKey = session.GetEncryptionKey(Global.EncryptionKey);
					var encryptionIV = session.GetEncryptionIV(Global.EncryptionKey);
					if (!header.TryGetValue("x-session-id", out var sessionID) || !sessionID.Decrypt(encryptionKey, encryptionIV).Equals(session.GetEncryptedID())
						|| !header.TryGetValue("x-device-id", out var deviceID) || !deviceID.Decrypt(encryptionKey, encryptionIV).Equals(session.DeviceID))
						throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");

					// update session
					session.AppName = body?.Get<string>("x-app-name") ?? session.AppName;
					session.AppPlatform = body?.Get<string>("x-app-platform") ?? session.AppPlatform;
					await websocket.PrepareConnectionInfoAsync(correlationID, session, Global.CancellationToken, WebSocketAPIs.Logger).ConfigureAwait(false);

					// update status
					websocket.SetStatus("Authenticated");
					websocket.Set("Token", JSONWebToken.DecodeAsJson(appToken, Global.JWTKey));
					await Task.WhenAll
					(
						session.SendSessionStateAsync(true, correlationID),
						Global.IsVisitLogEnabled ? Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.Visits", $"The connection of the WebSocket APIs was authenticated" + "\r\n" + websocket.GetConnectionInfo(session) + "\r\n" + $"- Status: {websocket.GetStatus()}", null, Global.ServiceName, LogLevel.Information, correlationID) : Task.CompletedTask,
						Global.IsDebugLogEnabled ? Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs", $"Successfully authenticate the session" + "\r\n" + $"{websocket.GetConnectionInfo(session)}" + "\r\n" + $"- Request: {requestObj.ToJson().ToString(Formatting.None)}" + "\r\n" + $"- Session: {session.ToJson().ToString(Formatting.None)}", null, Global.ServiceName, LogLevel.Information, correlationID) : Task.CompletedTask
					).ConfigureAwait(false);
				}

				// response to a heartbeat => refresh the session
				else if ("PONG".IsEquals(verb))
					await Task.WhenAll
					(
						new CommunicateMessage("Users")
						{
							Type = "Session#State",
							Data = new JObject
							{
								{ "SessionID", session.SessionID },
								{ "UserID", session.User.ID },
								{ "IsOnline", true }
							}
						}.PublishAsync(WebSocketAPIs.Logger, "Http.APIs"),
						Global.IsDebugLogEnabled ? Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs", $"Successfully send an inter-communicate message to refresh a session when got a response of a heartbeat signal" + "\r\n" + websocket.GetConnectionInfo(session), null, Global.ServiceName, LogLevel.Information, correlationID) : Task.CompletedTask
					).ConfigureAwait(false);

				// unknown
				else
					throw new InvalidRequestException();
			}
			catch (Exception ex)
			{
				await Task.WhenAll
				(
					websocket.SendAsync(ex, correlationID, requestObj.Get<string>("ID")),
					Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs",
						$"Error occurred while processing the session" + "\r\n" +
						$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
						$"- Status: {websocket.GetStatus()}" + "\r\n" +
						$"- Request: {requestObj.ToJson().ToString(RESTfulAPIs.JsonFormat)}" + "\r\n" +
						$"- Session: {session.ToJson().ToString(RESTfulAPIs.JsonFormat)}" + "\r\n" +
						$"- Error: {ex.Message}"
					, ex, Global.ServiceName, LogLevel.Error, correlationID)
				).ConfigureAwait(false);
				if (ex is InvalidSessionException)
					await WebSocketAPIs.WebSocket.CloseWebSocketAsync(websocket, WebSocketCloseStatus.PolicyViolation, ex.Message).ConfigureAwait(false);
			}
		}

		static async Task ProcessRequestAsync(this ManagedWebSocket websocket, ExpandoObject requestObj, Session session = null, string correlationID = null)
		{
			session = session ?? websocket.Get<Session>("Session");
			correlationID = correlationID ?? UtilityService.NewUUID;

			var requestInfo = new RequestInfo
			{
				Session = session,
				CorrelationID = correlationID
			};

			try
			{
				// prepare the requesting information
				var serviceName = requestObj.Get("ServiceName", "").GetANSIUri(true, true);
				var objectName = requestObj.Get("ObjectName", "").GetANSIUri(true, true);
				var verb = requestObj.Get("Verb", "GET").ToUpper();
				var query = new Dictionary<string, string>(requestObj.Get("Query", new Dictionary<string, string>()), StringComparer.OrdinalIgnoreCase);
				query.TryGetValue("object-identity", out var objectIdentity);
				var header = new Dictionary<string, string>(requestObj.Get("Header", new Dictionary<string, string>()), StringComparer.OrdinalIgnoreCase);
				if (!header.ContainsKey("x-app-token"))
				{
					var token = websocket.Get<JObject>("Token");
					token["iat"] = DateTime.Now.ToUnixTimestamp();
					header["x-app-token"] = JSONWebToken.Encode(token, Global.JWTKey);
				}
				var body = requestObj.Get("Body");
				if (verb.IsEquals("GET") && query.Remove("x-body", out var requestBody))
					try
					{
						body = requestBody.Url64Decode();
					}
					catch (Exception ex)
					{
						await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs", $"Error occurred while parsing body of the 'x-body' parameter => {ex.Message}", ex).ConfigureAwait(false);
					}
				var extra = new Dictionary<string, string>(requestObj.Get("Extra", new Dictionary<string, string>()), StringComparer.OrdinalIgnoreCase);
				if (verb.IsEquals("GET") && query.Remove("x-request-extra", out var extraInfo) && !string.IsNullOrWhiteSpace(extraInfo))
					try
					{
						extra = extraInfo.Url64Decode().ToExpandoObject().ToDictionary(kvp => kvp.Key, kvp => kvp.Value?.ToString(), StringComparer.OrdinalIgnoreCase);
					}
					catch { }

				requestInfo = new RequestInfo(session, serviceName, objectName, verb, query, header)
				{
					Body = body == null ? "" : body is string ? body as string : body.ToJson().ToString(Formatting.None),
					Extra = extra,
					CorrelationID = correlationID
				};

				// special: working with users
				if (requestInfo.ServiceName.IsEquals("users"))
				{
					// stop process when request to work with users' sessions
					if ("session".IsEquals(requestInfo.ObjectName))
						throw new InvalidRequestException("Please change to use RESTful APIs for working with users' sessions");

					// prepare related information
					if ("account".IsEquals(requestInfo.ObjectName) || "otp".IsEquals(requestInfo.ObjectName))
						requestInfo.PrepareAccountRelated(async (msg, ex) => await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs", msg, ex, Global.ServiceName, LogLevel.Error, correlationID).ConfigureAwait(false));

					// validate captcha
					requestInfo.CaptchaIsValid();

					// prepare signature
					requestInfo.Extra["Signature"] = requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT")
						? requestInfo.Body.GetHMACSHA256(Global.ValidationKey)
						: requestInfo.Header["x-app-token"].GetHMACSHA256(Global.ValidationKey);
				}

				// special: working with files
				else if (requestInfo.ServiceName.IsEquals("files"))
				{
					requestInfo.Extra["Signature"] = requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT")
						? requestInfo.Body.GetHMACSHA256(Global.ValidationKey)
						: requestInfo.Header["x-app-token"].GetHMACSHA256(Global.ValidationKey);
					requestInfo.Extra["SessionID"] = requestInfo.Session.SessionID.GetHMACBLAKE256(Global.ValidationKey);
				}

				// call the service
				var response = Global.StaticSegments.Contains(requestInfo.ServiceName.ToLower())
					? verb.IsEquals("GET")
						? (await Global.GetStaticFileContentAsync(Global.GetStaticFilePath([requestInfo.ServiceName.ToLower(), requestInfo.ObjectName.ToLower(), objectIdentity])).ConfigureAwait(false)).GetString().ToJson()
						: throw new MethodNotAllowedException(verb)
					: requestInfo.ServiceName.IsEquals("discovery")
						? requestInfo.ObjectName.IsEquals("controllers")
							? RESTfulAPIs.GetControllers()
							: requestInfo.ObjectName.IsEquals("services")
								? RESTfulAPIs.GetServices()
								: requestInfo.ObjectName.IsEquals("definitions")
									? await Global.CallServiceAsync(requestInfo.PrepareDefinitionRelated(), Global.CancellationToken, WebSocketAPIs.Logger, "Http.APIs").ConfigureAwait(false)
									: throw new InvalidRequestException("Unknown request")
						: requestInfo.ServiceName.IsEquals("cache")
							? await requestInfo.FlushCachingStoragesAsync().ConfigureAwait(false)
							: RESTfulAPIs.ServiceForwarders.ContainsKey(requestInfo.ServiceName.ToLower())
								? await requestInfo.ForwardRequestAsync(Global.CancellationToken).ConfigureAwait(false)
								: verb.IsEquals("PATCH")
									? "rollback".IsEquals(requestInfo.GetParameter("x-patch-mode"))
										? await requestInfo.RollbackAsync(Global.CancellationToken).ConfigureAwait(false)
										: "restore".IsEquals(requestInfo.GetParameter("x-patch-mode"))
											? await requestInfo.RestoreAsync(Global.CancellationToken).ConfigureAwait(false)
											: throw new InvalidRequestException("Unknown request")
									: await Global.CallServiceAsync(requestInfo, Global.CancellationToken, WebSocketAPIs.Logger, "Http.APIs").ConfigureAwait(false);

				// send the response as an update message
				await websocket.SendAsync(new UpdateMessage
				{
					Type = $"{requestInfo.ServiceName}{(string.IsNullOrWhiteSpace(requestInfo.ObjectName) ? "" : $"#{("Versions".IsEquals(requestInfo.ObjectName) ? objectIdentity : requestInfo.ObjectName)}#{("Versions".IsEquals(requestInfo.ObjectName) || "Refresh".IsEquals(objectIdentity) ? "Update" : !string.IsNullOrWhiteSpace(objectIdentity) && !objectIdentity.IsValidUUID() ? objectIdentity : verb).GetCapitalizedFirstLetter()}")}",
					Data = response
				}, requestObj.Get<string>("ID"), correlationID).ConfigureAwait(false);
			}
			catch (RemoteServerException ex)
			{
				var error = requestInfo.GetForwardingRequestError(ex);
				try
				{
					await websocket.SendAsync(new JObject
					{
						{ "ID", requestObj.Get<string>("ID") },
						{ "CorrelationID", correlationID },
						{ "Type", "Error" },
						{ "Data", error.Item2 }
					}, Global.CancellationToken).ConfigureAwait(false);
				}
				catch (Exception e)
				{
					WebSocketAPIs.Logger.LogError($"Error occurred while sending an error message via WebSocket => {e.Message}", e);
				}
				await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.APIs", error.Item2.Get<string>("Message"), ex, Global.ServiceName, LogLevel.Error, correlationID, $"Request: {requestObj.ToJson().ToString(RESTfulAPIs.JsonFormat)}\r\nWebSocket Info:\r\n{websocket.GetConnectionInfo()}").ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await websocket.SendAsync(ex, correlationID, requestObj.Get<string>("ID"), $"Request: {requestObj.ToJson().ToString(RESTfulAPIs.JsonFormat)}").ConfigureAwait(false);
			}
		}
	}
}