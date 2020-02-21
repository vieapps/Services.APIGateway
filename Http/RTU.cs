#region Related components
using System;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Collections.Generic;
using System.Collections.Concurrent;
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
	internal static class RTU
	{
		public static Components.WebSockets.WebSocket WebSocket { get; private set; }

		public static ILogger Logger { get; set; }

		public static void Initialize()
		{
			RTU.WebSocket = new Components.WebSockets.WebSocket(Components.Utility.Logger.GetLoggerFactory(), Global.CancellationTokenSource.Token)
			{
				OnError = async (websocket, exception) => await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs", $"Got an error while processing => {exception.Message} ({websocket?.ID} {websocket?.RemoteEndPoint})", exception).ConfigureAwait(false),
				OnConnectionEstablished = async websocket => await websocket.WhenConnectionIsEstablishedAsync().ConfigureAwait(false),
				OnConnectionBroken = async websocket => await websocket.WhenConnectionIsBrokenAsync().ConfigureAwait(false),
				OnMessageReceived = async (websocket, result, data) => await websocket.WhenMessageIsReceivedAsync(result, data).ConfigureAwait(false),
				KeepAliveInterval = TimeSpan.FromSeconds(45)
			};
			Global.Logger.LogInformation($"WebSocket ({Global.ServiceName} RTU) is initialized - Buffer size: {Components.WebSockets.WebSocket.ReceiveBufferSize:#,##0} bytes - Keep-Alive interval: {RTU.WebSocket.KeepAliveInterval.TotalSeconds} second(s)");
		}

		public static void Dispose()
		{
			RTU.WebSocket.Dispose();
			Global.Logger.LogInformation($"WebSocket ({Global.ServiceName} RTU) is stopped");
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
				await websocket.PrepareConnectionInfoAsync(correlationID, session).ConfigureAwait(false);

				// wait for few times before connecting to API Gateway Router because RxNET needs that
				if (query.ContainsKey("x-restart"))
					await Task.WhenAll(
						websocket.SendAsync(new UpdateMessage { Type = "Knock" }),
						Task.Delay(345, Global.CancellationTokenSource.Token)
					).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await RTU.WebSocket.CloseWebSocketAsync(websocket, ex is InvalidRequestException ? WebSocketCloseStatus.InvalidPayloadData : WebSocketCloseStatus.InternalServerError, ex is InvalidRequestException ? $"Request is invalid => {ex.Message}" : ex.Message).ConfigureAwait(false);
				return;
			}

			// subscribe an updater to push messages to client device
			websocket.Set("Updater", Services.Router.IncomingChannel.RealmProxy.Services
				.GetSubject<UpdateMessage>("messages.update")
				.Subscribe(
					async message => await websocket.PushAsync(message).ConfigureAwait(false),
					async exception => await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs", $"Error occurred while fetching an updating message => {exception.Message}", exception).ConfigureAwait(false)
				)
			);

			// subscribe a communicator to update related information
			websocket.Set("Communicator", Services.Router.IncomingChannel.RealmProxy.Services
				.GetSubject<CommunicateMessage>("messages.services.apigateway")
				.Subscribe(
					async message => await websocket.CommunicateAsync(message).ConfigureAwait(false),
					async exception => await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs", $"Error occurred while fetching an inter-communicating message => {exception.Message}", exception).ConfigureAwait(false)
				)
			);

			// update status
			websocket.SetStatus("Connected");
			if (Global.IsVisitLogEnabled)
				await Global.WriteLogsAsync(RTU.Logger, "Http.Visits", $"The real-time updater (RTU) is started" + "\r\n" + websocket.GetConnectionInfo() + "\r\n" + $"- Status: {websocket.GetStatus()}", null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);
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
					await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs", $"Error occurred while disposing updater: {session?.ToJson()?.ToString(Global.IsDebugResultsEnabled ? Formatting.Indented : Formatting.None)}", ex, Global.ServiceName, LogLevel.Error, correlationID).ConfigureAwait(false);
				}

			// remove the communicator
			if (websocket.Remove("Communicator", out IDisposable communicator))
				try
				{
					communicator?.Dispose();
				}
				catch (Exception ex)
				{
					await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs", $"Error occurred while disposing communicator: {session?.ToJson()?.ToString(Global.IsDebugResultsEnabled ? Formatting.Indented : Formatting.None)}", ex, Global.ServiceName, LogLevel.Error, correlationID).ConfigureAwait(false);
				}

			// update the session state
			await Task.WhenAll(
				session != null ? session.SendSessionStateAsync(false, correlationID) : Task.CompletedTask,
				Global.IsVisitLogEnabled ? Global.WriteLogsAsync(RTU.Logger, "Http.Visits", $"The real-time updater (RTU) is stopped" + "\r\n" + websocket.GetConnectionInfo(session) + "\r\n" + $"- Served times: {websocket.Timestamp.GetElapsedTimes()}", null, Global.ServiceName, LogLevel.Information, correlationID) : Task.CompletedTask
			).ConfigureAwait(false);
		}

		static async Task WhenMessageIsReceivedAsync(this ManagedWebSocket websocket, WebSocketReceiveResult result, byte[] data)
		{
			// prepare
			var stopwatch = Stopwatch.StartNew();
			var correlationID = UtilityService.NewUUID;

			// check message
			var requestMsg = result.MessageType.Equals(WebSocketMessageType.Text) ? data.GetString() : null;
			if (string.IsNullOrWhiteSpace(requestMsg))
				return;

			// wait for the initializing process is completed
			while ("Initializing".IsEquals(websocket.GetStatus()))
				await Task.Delay(UtilityService.GetRandomNumber(123, 456), Global.CancellationTokenSource.Token).ConfigureAwait(false);

			// check session
			var session = websocket.Get<Session>("Session");
			if (session == null)
			{
				await Task.WhenAll(
					Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs", $"No session is attached - Request: {requestMsg}", null, Global.ServiceName, LogLevel.Critical, correlationID),
					RTU.WebSocket.CloseWebSocketAsync(websocket, WebSocketCloseStatus.PolicyViolation, "No session")
				).ConfigureAwait(false);
				return;
			}

			// prepare
			var requestObj = requestMsg.ToExpandoObject();
			var serviceName = requestObj.Get("ServiceName", "");
			var objectName = requestObj.Get("ObjectName", "");
			var verb = requestObj.Get("Verb", "GET").ToUpper();
			var query = new Dictionary<string, string>(requestObj.Get("Query", new Dictionary<string, string>()), StringComparer.OrdinalIgnoreCase);
			query.TryGetValue("object-identity", out var objectIdentity);

			// visit logs
			if (Global.IsVisitLogEnabled)
				await Global.WriteLogsAsync(RTU.Logger, "Http.Visits",
					$"Request starting {verb} " + $"/{serviceName}{(string.IsNullOrWhiteSpace(objectName) ? "" : $"/{objectName}")}{(string.IsNullOrWhiteSpace(objectIdentity) ? "" : $"/{objectIdentity}")}".ToLower() + (query.TryGetValue("x-request", out var xrequest) ? $"?x-request={xrequest}" : "") + " HTTPWS/1.1" + " \r\n" +
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
								await Task.Delay(UtilityService.GetRandomNumber(123, 456), Global.CancellationTokenSource.Token).ConfigureAwait(false);
								if ("Authenticated".IsEquals(websocket.GetStatus()))
									cts.Cancel();
							}
							catch { }
					}

				// process the request
				if ("Authenticated".IsEquals(websocket.GetStatus()))
					await websocket.ProcessRequestAsync(requestObj, session, correlationID).ConfigureAwait(false);
				else
					await Task.WhenAll(
						Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs",
							$"Session is not authenticated" + "\r\n" +
							$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
							$"- Status: {websocket.GetStatus()}"
						, null, Global.ServiceName, LogLevel.Critical, correlationID),
						RTU.WebSocket.CloseWebSocketAsync(websocket, WebSocketCloseStatus.PolicyViolation, "Need to authenticate the session")
					).ConfigureAwait(false);
			}

			// visit logs
			stopwatch.Stop();
			if (Global.IsVisitLogEnabled)
				await Global.WriteLogsAsync(RTU.Logger, "Http.Visits", $"Request finished in {stopwatch.GetElapsedTimes()}", null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);
		}

		static async Task PrepareConnectionInfoAsync(this ManagedWebSocket websocket, string correlationID = null, Session session = null)
		{
			session = session ?? websocket.Get<Session>("Session");
			var account = "Visitor";
			if (!string.IsNullOrWhiteSpace(session?.User?.ID))
				try
				{
					var json = await Global.CallServiceAsync(new RequestInfo(session, "Users", "Profile", "GET"), Global.CancellationTokenSource.Token, RTU.Logger, "Http.InternalAPIs").ConfigureAwait(false);
					account = $"{json?.Get("Name", "Unknown")} ({session.User.ID})";
				}
				catch (Exception ex)
				{
					account = $"Unknown ({session.User.ID})";
					await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs", $"Error occurred while fetching an account profile => {ex.Message}", ex).ConfigureAwait(false);
				}
			websocket.Set("AccountInfo", account);
			websocket.Set("LocationInfo", session != null ? await session.GetLocationAsync(correlationID, Global.CancellationTokenSource.Token).ConfigureAwait(false) : "Unknown");
		}

		static string GetConnectionInfo(this ManagedWebSocket websocket, Session session = null)
		{
			session = session ?? websocket.Get<Session>("Session");
			return $"- Account: {websocket.Get("AccountInfo", "Visitor")} - Session ID: {session?.SessionID ?? "Unknown"} - Device ID: {session?.DeviceID ?? "Unknown"} - Origin: {(websocket.Headers.TryGetValue("Origin", out var origin) ? origin : session?.AppOrigin ?? "Unknown")}" + "\r\n" +
				$"- App: {session?.AppName ?? "Unknown"} @ {session?.AppPlatform ?? "Unknown"} [{session?.AppAgent ?? "Unknown"}]" + "\r\n" +
				$"- Connection IP: {session?.IP ?? "Unknown"} - Location: {websocket.Get("LocationInfo", "Unknown")} - WebSocket: {websocket.ID} @ {websocket.RemoteEndPoint}";
		}

		static void SetStatus(this ManagedWebSocket websocket, string status)
			=> websocket.Set("Status", status);

		static string GetStatus(this ManagedWebSocket websocket)
			=> websocket.Get<string>("Status");

		static async Task SendAsync(this ManagedWebSocket websocket, Exception exception, string msg = null, string correlationID = null, string identity = null, string additionalMsg = null)
		{
			// prepare
			correlationID = correlationID ?? UtilityService.NewUUID;
			var wampException = exception is WampException
				? (exception as WampException).GetDetails()
				: null;

			msg = msg ?? wampException?.Item2 ?? exception.Message;
			var type = wampException?.Item3 ?? exception?.GetType().GetTypeName(true);
			var code = wampException != null ? wampException.Item1 : exception.GetHttpStatusCode();

			var message = new JObject
			{
				{ "Message", msg },
				{ "Type", type },
				{ "Code", code },
				{ "CorrelationID", correlationID }
			};

			if (Global.IsDebugStacksEnabled)
			{
				if (wampException != null)
					message["Stack"] = wampException.Item4;

				else
				{
					message["Stack"] = exception.StackTrace;
					if (exception.InnerException != null)
					{
						var inners = new JArray();
						var counter = 1;
						var inner = exception.InnerException;
						while (inner != null)
						{
							inners.Add(new JObject
							{
								{ "Error", "(" + counter + "): " + inner.Message + " [" + inner.GetType().ToString() + "]" },
								{ "Stack", inner.StackTrace }
							});
							counter++;
							inner = inner.InnerException;
						}
						message["Inners"] = inners;
					}
				}
			}

			// send & write logs
			message = new JObject
			{
				{ "Type", "Error" },
				{ "Data", message }
			};
			if (!string.IsNullOrWhiteSpace(identity))
				message["ID"] = identity;

			await Task.WhenAll(
				websocket.SendAsync(message.ToString(Formatting.None), true, Global.CancellationTokenSource.Token),
				Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs", msg ?? exception.Message, exception, Global.ServiceName, LogLevel.Error, correlationID, string.IsNullOrWhiteSpace(additionalMsg) ? null : $"{additionalMsg}\r\nWebSocket Info:\r\n{websocket.GetConnectionInfo()}")
			).ConfigureAwait(false);
		}

		static Task SendAsync(this ManagedWebSocket websocket, UpdateMessage message, string identity = null)
			=> websocket.SendAsync(message.ToJson(json =>
			{
				(json as JObject).Remove("DeviceID");
				(json as JObject).Remove("ExcludedDeviceID");
				if (!string.IsNullOrWhiteSpace(identity))
					json["ID"] = identity;
			}).ToString(Formatting.None), true, Global.CancellationTokenSource.Token);

		static async Task PushAsync(this ManagedWebSocket websocket, UpdateMessage message)
		{
			if ("Disconnected".IsEquals(websocket.GetStatus()))
				return;

			var session = websocket.Get<Session>("Session");
			if (session == null || session.DeviceID.IsEquals(message.ExcludedDeviceID) || (!"*".Equals(message.DeviceID) && !session.DeviceID.IsEquals(message.DeviceID)))
				return;

			var correlationID = UtilityService.NewUUID;
			try
			{
				await websocket.SendAsync(message).ConfigureAwait(false);
				if (Global.IsDebugLogEnabled)
					await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs",
						$"Successfully push a message to the device ({message.DeviceID})" + "\r\n" +
						$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
						$"- Type: {message.Type}" + "\r\n" +
						$"- Message: {message.Data.ToString(Formatting.None)}"
					, null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);
			}
			catch (ObjectDisposedException) { }
			catch (Exception ex)
			{
				await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs",
					$"Error occurred while pushing a message to the device ({message.DeviceID}) => {ex.Message}" + "\r\n" +
					$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
					$"- Type: {message.Type}" + "\r\n" +
					$"- Message: {message.ToJson().ToString(InternalAPIs.JsonFormat)}"
				, ex, Global.ServiceName, LogLevel.Error, correlationID).ConfigureAwait(false);
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
					await Global.UpdateWithAuthenticateTokenAsync(session, authenticateToken, null, null, null, RTU.Logger, "Http.InternalAPIs", correlationID).ConfigureAwait(false);
					if (!await session.IsSessionExistAsync(RTU.Logger, "Http.InternalAPIs", correlationID).ConfigureAwait(false))
						throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
					else if (!session.SessionID.Equals(session.GetDecryptedID(encryptedSessionID, Global.EncryptionKey, Global.ValidationKey)))
						throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
					await websocket.PrepareConnectionInfoAsync(correlationID, session).ConfigureAwait(false);
					if (Global.IsDebugLogEnabled)
						await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs",
							$"Successfully process an inter-communicate message (patch session - {message.Data.Get<string>("SessionID")} => {session.SessionID})" + "\r\n" +
							$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
							$"- Type: {message.Type}" + "\r\n" +
							$"- Message: {message.Data.ToString(Formatting.None)}"
						, null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);
				}

				// update the session with new users' privileges => new access token
				else if (message.Type.IsEquals("Session#Update"))
				{
					session.User = message.Data["User"] == null ? session.User : message.Data.Get<JObject>("User").Copy<User>();
					session.Verified = message.Data.Get<bool>("Verified");
					await websocket.SendAsync(new UpdateMessage
					{
						Type = "Users#Session#Update",
						Data = session.GetSessionJson()
					}).ConfigureAwait(false);
					if (Global.IsDebugLogEnabled)
						await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs",
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
					await Task.WhenAll(
						Global.Cache.SetAsync($"Session#{session.SessionID}", session.GetEncryptedID(), 13),
						websocket.SendAsync(new UpdateMessage
						{
							Type = "Users#Session#Revoke",
							Data = session.GetSessionJson()
						})
					).ConfigureAwait(false);
					if (Global.IsDebugLogEnabled)
						await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs",
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
				await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs",
					$"Error occurred while processing an inter-communicate message => {ex.Message}" + "\r\n" +
					$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
					$"- Type: {message.Type}" + "\r\n" +
					$"- Message: {message.ToJson().ToString(InternalAPIs.JsonFormat)}"
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
					var appToken = body?.Get<string>("x-app-token");
					await Global.UpdateWithAuthenticateTokenAsync(session, appToken, null, null, null, RTU.Logger, "Http.InternalAPIs", correlationID).ConfigureAwait(false);
					if (!await session.IsSessionExistAsync(RTU.Logger, "Http.InternalAPIs", correlationID).ConfigureAwait(false))
						throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");

					// verify identity of session and device
					var encryptionKey = session.GetEncryptionKey(Global.EncryptionKey);
					var encryptionIV = session.GetEncryptionIV(Global.EncryptionKey);
					var header = new Dictionary<string, string>(requestObj.Get("Header", new Dictionary<string, string>()), StringComparer.OrdinalIgnoreCase);
					if (!header.TryGetValue("x-session-id", out var sessionID)
						|| !session.SessionID.Equals(session.GetDecryptedID(sessionID.Decrypt(encryptionKey, encryptionIV), Global.EncryptionKey, Global.ValidationKey))
						|| !header.TryGetValue("x-device-id", out var deviceID)
						|| !session.DeviceID.Equals(deviceID.Decrypt(encryptionKey, encryptionIV)))
						throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");

					// update session
					session.AppName = body?.Get<string>("x-app-name") ?? session.AppName;
					session.AppPlatform = body?.Get<string>("x-app-platform") ?? session.AppPlatform;
					await websocket.PrepareConnectionInfoAsync(correlationID, session).ConfigureAwait(false);

					// update status
					websocket.SetStatus("Authenticated");
					websocket.Set("Token", JSONWebToken.DecodeAsJson(appToken, Global.JWTKey));
					await Task.WhenAll(
						session.SendSessionStateAsync(true, correlationID),
						Global.IsVisitLogEnabled ? Global.WriteLogsAsync(RTU.Logger, "Http.Visits", $"The real-time updater (RTU) is authenticated" + "\r\n" + websocket.GetConnectionInfo(session) + "\r\n" + $"- Status: {websocket.GetStatus()}", null, Global.ServiceName, LogLevel.Information, correlationID) : Task.CompletedTask,
						Global.IsDebugLogEnabled ? Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs", $"Successfully authenticate the session" + "\r\n" + $"{websocket.GetConnectionInfo(session)}" + "\r\n" + $"- Request: {requestObj.ToJson().ToString(Formatting.None)}" + "\r\n" + $"- Session: {session.ToJson().ToString(Formatting.None)}", null, Global.ServiceName, LogLevel.Information, correlationID) : Task.CompletedTask
					).ConfigureAwait(false);
				}

				// response to a heartbeat => refresh the session
				else if ("PONG".IsEquals(verb))
					await Task.WhenAll(
						new CommunicateMessage("Users")
						{
							Type = "Session#State",
							Data = new JObject
							{
								{ "SessionID", session.SessionID },
								{ "UserID", session.User.ID },
								{ "IsOnline", true }
							}
						}.PublishAsync(RTU.Logger, "Http.InternalAPIs"),
						Global.IsDebugLogEnabled ? Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs", $"Successfully send an inter-communicate message to refresh a session when got a response of a heartbeat signal" + "\r\n" + websocket.GetConnectionInfo(session), null, Global.ServiceName, LogLevel.Information, correlationID) : Task.CompletedTask
					).ConfigureAwait(false);

				// unknown
				else
					throw new InvalidRequestException();
			}
			catch (Exception ex)
			{
				await Task.WhenAll(
					websocket.SendAsync(ex, null, correlationID, requestObj.Get<string>("ID")),
					Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs",
						$"Error occurred while processing the session" + "\r\n" +
						$"{websocket.GetConnectionInfo(session)}" + "\r\n" +
						$"- Status: {websocket.GetStatus()}" + "\r\n" +
						$"- Request: {requestObj.ToJson().ToString(InternalAPIs.JsonFormat)}" + "\r\n" +
						$"- Session: {session.ToJson().ToString(InternalAPIs.JsonFormat)}" + "\r\n" +
						$"- Error: {ex.Message}"
					, ex, Global.ServiceName, LogLevel.Error, correlationID)
				).ConfigureAwait(false);
				if (ex is InvalidSessionException)
					await RTU.WebSocket.CloseWebSocketAsync(websocket, WebSocketCloseStatus.PolicyViolation, ex.Message).ConfigureAwait(false);
			}
		}

		static async Task ProcessRequestAsync(this ManagedWebSocket websocket, ExpandoObject requestObj, Session session = null, string correlationID = null)
		{
			session = session ?? websocket.Get<Session>("Session");
			correlationID = correlationID ?? UtilityService.NewUUID;
			try
			{
				// prepare the requesting information
				var serviceName = requestObj.Get("ServiceName", "");
				var objectName = requestObj.Get("ObjectName", "");
				var verb = requestObj.Get("Verb", "GET").ToUpper();
				var query = new Dictionary<string, string>(requestObj.Get("Query", new Dictionary<string, string>()), StringComparer.OrdinalIgnoreCase);
				query.TryGetValue("object-identity", out string objectIdentity);
				var header = new Dictionary<string, string>(requestObj.Get("Header", new Dictionary<string, string>()), StringComparer.OrdinalIgnoreCase);
				if (!header.ContainsKey("x-app-token"))
				{
					var token = websocket.Get<JObject>("Token");
					token["iat"] = DateTime.Now.ToUnixTimestamp();
					header["x-app-token"] = JSONWebToken.Encode(token, Global.JWTKey);
				}
				var extra = new Dictionary<string, string>(requestObj.Get("Extra", new Dictionary<string, string>()), StringComparer.OrdinalIgnoreCase);
				var body = requestObj.Get("Body");
				var requestInfo = new RequestInfo
				{
					Session = session,
					ServiceName = serviceName,
					ObjectName = objectName,
					Verb = verb,
					Query = query,
					Header = header,
					Body = body == null ? "" : body is string ? body as string : body.ToJson().ToString(Formatting.None),
					Extra = extra,
					CorrelationID = correlationID
				};

				// special: working with users
				if (requestInfo.ServiceName.IsEquals("users"))
				{
					// stop process when request to work with users' sessions
					if ("session".IsEquals(requestInfo.ObjectName))
						throw new InvalidRequestException("Please change to use REST APIs for working with users' sessions");

					// prepare related information
					if (requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT"))
					{
						requestInfo.CaptchaIsValid();
						if ("account".IsEquals(requestInfo.ObjectName) || "otp".IsEquals(requestInfo.ObjectName))
							requestInfo.PrepareAccountRelated(null, async (msg, ex) => await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs", msg, ex, Global.ServiceName, LogLevel.Error, correlationID).ConfigureAwait(false));
					}
					else if ("otp".IsEquals(requestInfo.ObjectName) && requestInfo.Verb.IsEquals("DELETE"))
						requestInfo.PrepareAccountRelated(null, async (msg, ex) => await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs", msg, ex, Global.ServiceName, LogLevel.Error, correlationID).ConfigureAwait(false));

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
						? (await Global.GetStaticFileContentAsync(Global.GetStaticFilePath(new[] { requestInfo.ServiceName.ToLower(), requestInfo.ObjectName.ToLower(), objectIdentity })).ConfigureAwait(false)).GetString().ToJson()
						: throw new MethodNotAllowedException(verb)
					: requestInfo.ServiceName.IsEquals("discovery")
						? requestInfo.ObjectName.IsEquals("controllers")
							? InternalAPIs.GetControllers()
							: requestInfo.ObjectName.IsEquals("services")
								? InternalAPIs.GetServices()
								: requestInfo.ObjectName.IsEquals("definitions")
									? await Global.CallServiceAsync(requestInfo.PrepareDefinitionRelated(), Global.CancellationTokenSource.Token, RTU.Logger, "Http.InternalAPIs").ConfigureAwait(false)
									: throw new InvalidRequestException("Unknown request")
						: await Global.CallServiceAsync(requestInfo, Global.CancellationTokenSource.Token, RTU.Logger, "Http.InternalAPIs").ConfigureAwait(false);

				// send the response as an update message
				await websocket.SendAsync(new UpdateMessage
				{
					Type = serviceName.GetCapitalizedFirstLetter() + (string.IsNullOrWhiteSpace(objectName) ? "" : "#" + objectName.GetCapitalizedFirstLetter() + "#" + (!string.IsNullOrWhiteSpace(objectIdentity) && !objectIdentity.IsValidUUID() ? objectIdentity : verb).GetCapitalizedFirstLetter()),
					Data = response
				}, requestObj.Get<string>("ID")).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await websocket.SendAsync(ex, null, correlationID, requestObj.Get<string>("ID"), $"Request: {requestObj.ToJson().ToString(InternalAPIs.JsonFormat)}").ConfigureAwait(false);
			}
		}
	}
}