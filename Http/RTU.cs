#region Related components
using System;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Dynamic;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using WampSharp.V2.Core.Contracts;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.WebSockets;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class RTU
	{
		internal static Components.WebSockets.WebSocket WebSocket { get; private set; }

		internal static ILogger Logger { get; set; }

		internal static void Initialize()
		{
			RTU.WebSocket = new Components.WebSockets.WebSocket(Components.Utility.Logger.GetLoggerFactory(), Global.CancellationTokenSource.Token)
			{
				OnError = (websocket, exception) => Global.WriteLogs(RTU.Logger, "RTU", $"Got error while processing: {exception.Message} ({websocket?.ID} {websocket?.RemoteEndPoint})", exception),
				OnConnectionEstablished = (websocket) => Task.Run(() => websocket.WhenConnectionIsEstablishedAsync()).ConfigureAwait(false),
				OnConnectionBroken = (websocket) => Task.Run(() => websocket.WhenConnectionIsBrokenAsync()).ConfigureAwait(false),
				OnMessageReceived = (websocket, result, data) => Task.Run(() => websocket.WhenMessageIsReceivedAsync(result, data)).ConfigureAwait(false)
			};
			Components.WebSockets.WebSocket.AgentName = UtilityService.GetAppSetting("HttpServerName", "VIEApps NGX") + " WebSockets";
			Global.Logger.LogInformation($"WebSocket ({Global.ServiceName} RTU) is initialized - Buffer size: {Components.WebSockets.WebSocket.ReceiveBufferSize:#,##0} bytes - Keep-Alive interval: {RTU.WebSocket.KeepAliveInterval.TotalSeconds} second(s)");
		}

		internal static void Dispose()
		{
			RTU.WebSocket.Dispose();
			Global.Logger.LogInformation($"WebSocket ({Global.ServiceName} RTU) is stopped");
		}

		static async Task WhenConnectionIsEstablishedAsync(this ManagedWebSocket websocket)
		{
			// prepare
			var query = websocket.RequestUri.ParseQuery();
			Session session = null;
			try
			{
				var headers = websocket.Headers;
				var request = new ExpandoObject();
				if (query.ContainsKey("x-request"))
					try
					{
						request = query["x-request"].Url64Decode().ToExpandoObject();
					}
					catch (Exception ex)
					{
						throw new InvalidRequestException($"Request is invalid => {ex.Message}", ex);
					}

				if (!headers.TryGetValue("x-app-token", out string appToken))
					appToken = request.Get<string>("x-app-token");
				if (string.IsNullOrWhiteSpace(appToken))
					throw new TokenNotFoundException("Token is not found");

				session = Global.GetSession(query.ToNameValueCollection(), headers.TryGetValue("User-Agent", out string userAgent) ? userAgent : "", $"{(websocket.RemoteEndPoint as IPEndPoint).Address}", headers.TryGetValue("Referer", out string urlReferer) ? new Uri(urlReferer) : null);
				session.DeviceID = headers.TryGetValue("x-device-id", out string deviceID) ? deviceID : request.Get("x-device-id", session.DeviceID);
				session.AppName = headers.TryGetValue("x-app-name", out string appName) ? appName : request.Get("x-app-name", session.AppName);
				session.AppPlatform = headers.TryGetValue("x-app-platform", out string appPlatform) ? appPlatform : request.Get("x-app-platform", session.AppPlatform);

				if (string.IsNullOrWhiteSpace(session.DeviceID))
					throw new InvalidTokenException("Device identity is not found");

				// verify client credential
				await Global.UpdateWithAuthenticateTokenAsync(session, appToken).ConfigureAwait(false);
				if (!await Global.IsSessionExistAsync(session).ConfigureAwait(false))
					throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
			}
			catch (Exception ex)
			{
				await Global.WriteLogsAsync(RTU.Logger, "RTU", ex.Message, ex).ConfigureAwait(false);
				if (ex is TokenNotFoundException || ex is InvalidTokenException || ex is InvalidTokenSignatureException || ex is InvalidSessionException || ex is InvalidRequestException)
					await websocket.SendAsync(ex).ConfigureAwait(false);
				else
					await websocket.SendAsync(new InvalidRequestException($"Request is invalid => {ex.Message}", ex)).ConfigureAwait(false);
				RTU.WebSocket.CloseWebSocket(websocket, WebSocketCloseStatus.InvalidPayloadData, $"Request is invalid => {ex.Message}");
				return;
			}

			// update the initializing flag
			websocket.Set("__IsInitializing", "v");

			// wait for few times before connecting to WAMP router because Reactive.NET needs
			if (query.ContainsKey("x-restart"))
			{
				// send knock message
				await websocket.SendAsync(new UpdateMessage
				{
					Type = "Knock"
				}).ConfigureAwait(false);

				// wait for a few times
				try
				{
					await Task.Delay(456, Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					RTU.WebSocket.CloseWebSocket(websocket, WebSocketCloseStatus.InternalServerError, $"Error => {ex.Message}");
					return;
				}

				// re-register online session
				await session.SendOnlineStatusAsync(true).ConfigureAwait(false);
			}

			// extra information
			websocket.Set("Session", session);
			await websocket.PrepareConnectionInfoAsync().ConfigureAwait(false);

			// subscribe to push messages
			websocket.Set("Updater", WAMPConnections.IncomingChannel.RealmProxy.Services
				.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages")
				.Subscribe(
					async message =>
					{
						if (message.DeviceID.Equals("*") || message.DeviceID.IsEquals(session.DeviceID))
							try
							{
								await websocket.SendAsync(message).ConfigureAwait(false);
								if (Global.IsDebugResultsEnabled)
									await Global.WriteLogsAsync(RTU.Logger, "RTU", $"Push the message to the subscriber's device successful" + "\r\n" + websocket.GetConnectionInfo() + "\r\n" + $"- Message: {message.Data.ToString(Formatting.Indented)}").ConfigureAwait(false);
							}
							catch (Exception ex)
							{
								await Global.WriteLogsAsync(RTU.Logger, "RTU", $"Error occurred while pushing => {ex.Message}" + "\r\n" + websocket.GetConnectionInfo() + "\r\n" + $"- Message: {message.ToJson().ToString(Global.IsDebugResultsEnabled ? Formatting.Indented : Formatting.None)}", ex).ConfigureAwait(false);
							}
					},
					async exception => await Global.WriteLogsAsync(RTU.Logger, "RTU", $"Error occurred while fetching messages => {exception.Message}", exception).ConfigureAwait(false)
				)
			);

			if (Global.IsDebugLogEnabled)
				await Global.WriteLogsAsync(RTU.Logger, "RTU", $"The real-time updater of a client's device is started" + "\r\n" + websocket.GetConnectionInfo()).ConfigureAwait(false);

			// update the initializing flag
			websocket.Remove("__IsInitializing");
		}

		static async Task WhenConnectionIsBrokenAsync(this ManagedWebSocket websocket)
		{
			// remove the attached session
			websocket.Remove("Session", out Session session);

			// remove the updater
			if (websocket.Remove("Updater", out IDisposable updater))
				try
				{
					updater?.Dispose();
				}
				catch (Exception ex)
				{
					await Global.WriteLogsAsync(RTU.Logger, "RTU", $"Error occurred while disposing updater: {session?.ToJson()?.ToString(Global.IsDebugResultsEnabled ? Formatting.Indented : Formatting.None)}", ex).ConfigureAwait(false);
				}

			// update online status
			await Task.WhenAll(
				session != null ? session.SendOnlineStatusAsync(false) : Task.CompletedTask,
				session != null ? InternalAPIs.Cache.RemoveAsync($"Session#{session.SessionID}") : Task.CompletedTask,
				Global.IsDebugLogEnabled ? Global.WriteLogsAsync(RTU.Logger, "RTU", $"The real-time updater of a client's device is stopped" + "\r\n" + websocket.GetConnectionInfo()) : Task.CompletedTask
			).ConfigureAwait(false);
		}

		static async Task WhenMessageIsReceivedAsync(this ManagedWebSocket websocket, WebSocketReceiveResult result, byte[] data)
		{
			// prepare
			var correlationID = UtilityService.NewUUID;

			// check message
			var requestMsg = result.MessageType.Equals(WebSocketMessageType.Text) ? data.GetString() : null;
			if (string.IsNullOrWhiteSpace(requestMsg))
				return;

			// wait for the initializing process is completed
			while (websocket.Get<string>("__IsInitializing") != null)
				await Task.Delay(UtilityService.GetRandomNumber(123, 456), Global.CancellationTokenSource.Token).ConfigureAwait(false);

			// check session
			var session = websocket.Get<Session>("Session");
			if (session == null)
			{
				await Global.WriteLogsAsync(RTU.Logger, "RTU", $"No session is attached to this WebSocket ({websocket.ID} @ {websocket.RemoteEndPoint})", null, Global.ServiceName, LogLevel.Critical, correlationID).ConfigureAwait(false);
				RTU.WebSocket.CloseWebSocket(websocket, WebSocketCloseStatus.InternalServerError, "No attached session => need to restart");
				return;
			}

			// prepare information
			var requestObj = requestMsg.ToExpandoObject();
			var serviceName = requestObj.Get<string>("ServiceName");
			var objectName = requestObj.Get<string>("ObjectName");
			var verb = requestObj.Get("Verb", "GET").ToUpper();
			var query = new Dictionary<string, string>(requestObj.Get("Query", new Dictionary<string, string>()), StringComparer.OrdinalIgnoreCase);
			var header = new Dictionary<string, string>(requestObj.Get("Header", new Dictionary<string, string>()), StringComparer.OrdinalIgnoreCase);
			var extra = new Dictionary<string, string>(requestObj.Get("Extra", new Dictionary<string, string>()), StringComparer.OrdinalIgnoreCase);

			if (Global.IsDebugLogEnabled)
				await Global.WriteLogsAsync(RTU.Logger, "RTU", $"Begin process ({verb} /{serviceName}/{objectName}/{(query.ContainsKey("object-identity") ? query["object-identity"] : "")} - WebSocket: {websocket.ID} @ {websocket.RemoteEndPoint})", null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);

			// response to a heartbeat => refresh the session
			if ("PONG".IsEquals(verb) && "session".IsEquals(objectName))
				await Task.WhenAll(
					InternalAPIs.Cache.SetAsync($"Session#{session.SessionID}", session.GetEncryptedID(), 180, Global.CancellationTokenSource.Token),
					Global.IsDebugResultsEnabled
						? Global.WriteLogsAsync(RTU.Logger, "RTU", $"End process => Successfully refresh a session when got a response of a heartbeat signal" + "\r\n" + websocket.GetConnectionInfo(), null, Global.ServiceName, LogLevel.Information, correlationID)
						: Task.CompletedTask
				).ConfigureAwait(false);

			// update the session
			else if ("PATCH".IsEquals(verb) && "users".IsEquals(serviceName) && "session".IsEquals(objectName) && extra.ContainsKey("x-session"))
				try
				{
					// verify
					await Global.UpdateWithAuthenticateTokenAsync(session, header["x-app-token"]).ConfigureAwait(false);
					if (!await Global.IsSessionExistAsync(session).ConfigureAwait(false))
						throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
					else if (!session.SessionID.Equals(session.GetDecryptedID(extra["x-session"], Global.EncryptionKey, Global.ValidationKey)))
						throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");

					// patch
					await websocket.PrepareConnectionInfoAsync().ConfigureAwait(false);
					if (Global.IsDebugResultsEnabled)
						await Global.WriteLogsAsync(RTU.Logger, "RTU",
							$"End process => Successfully patch the session" + "\r\n" +
							$"{websocket.GetConnectionInfo()}" + "\r\n" +
							$"- Request: {requestObj?.ToJson()?.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" + "\r\n" +
							$"- Response: {session.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"
						, null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					await Task.WhenAll(
						websocket.SendAsync(ex),
						Global.WriteLogsAsync(RTU.Logger, "RTU",
							$"End process => Error occurred: {ex.Message}" + "\r\n" +
							$"{websocket.GetConnectionInfo()}" + "\r\n" +
							$"- Request: {requestObj?.ToJson()?.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" + "\r\n" +
							$"- Session (current): {session.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"
						, ex, Global.ServiceName, LogLevel.Error, correlationID)
					).ConfigureAwait(false);
				}

			// call service to process the request
			else if (!string.IsNullOrWhiteSpace(serviceName))
			{
				var stopwatch = Stopwatch.StartNew();
				try
				{
					// call the requested service
					var requestInfo = new RequestInfo
					{
						Session = session,
						ServiceName = serviceName,
						ObjectName = objectName,
						Verb = verb,
						Query = query,
						Header = header,
						Body = requestObj.Get("Body", ""),
						Extra = extra,
						CorrelationID = correlationID
					};

					if (serviceName.IsEquals("Users"))
					{
						if (verb.IsEquals("POST") || verb.IsEquals("PUT"))
							requestInfo.Extra["Signature"] = requestInfo.Body.GetHMACSHA256(Global.ValidationKey);
						else
						{
							if (!requestInfo.Header.ContainsKey("x-app-token"))
								requestInfo.Header["x-app-token"] = session.User.GetAuthenticateToken(Global.EncryptionKey, Global.JWTKey);
							requestInfo.Extra["Signature"] = requestInfo.Header["x-app-token"].GetHMACSHA256(Global.ValidationKey);
						}
					}

					var json = await Global.CallServiceAsync(requestInfo, Global.CancellationTokenSource.Token, RTU.Logger).ConfigureAwait(false);

					// send the update message
					var @event = requestInfo.GetObjectIdentity();
					@event = !string.IsNullOrWhiteSpace(@event) && !@event.IsValidUUID()
						? @event
						: verb;

					await websocket.SendAsync(new UpdateMessage
					{
						Type = serviceName.GetCapitalizedFirstLetter() + (string.IsNullOrWhiteSpace(objectName) ? "" : "#" + objectName.GetCapitalizedFirstLetter() + "#" + @event.GetCapitalizedFirstLetter()),
						DeviceID = session.DeviceID,
						Data = json
					}).ConfigureAwait(false);

					stopwatch.Stop();
					if (Global.IsDebugResultsEnabled)
						await Global.WriteLogsAsync(RTU.Logger, "RTU",
							$"End process => Success" + "\r\n" +
							$"{websocket.GetConnectionInfo()}" + "\r\n" +
							$"- Request: {requestObj.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" + "\r\n" +
							$"- Response: {json.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" + "\r\n" +
							$"- Execution times: {stopwatch.GetElapsedTimes()}"
						, null, Global.ServiceName, LogLevel.Information, correlationID).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					stopwatch.Stop();
					await Task.WhenAll(
						websocket.SendAsync(ex),
						Global.WriteLogsAsync(RTU.Logger, "RTU",
							$"End process => Error occurred: {ex.Message}" + "\r\n" +
							$"{websocket.GetConnectionInfo()}" + "\r\n" +
							$"- Request: {requestObj?.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" + "\r\n" +
							$"- Execution times: {stopwatch.GetElapsedTimes()}"
						, ex, Global.ServiceName, LogLevel.Error, correlationID)
					).ConfigureAwait(false);
				}
			}
		}

		static async Task PrepareConnectionInfoAsync(this ManagedWebSocket websocket)
		{
			var session = websocket.Get<Session>("Session") ?? Global.CurrentHttpContext.GetSession();
			var account = "Visitor";
			if (!string.IsNullOrWhiteSpace(session.User?.ID))
			{
				var profile = await WAMPConnections.CallServiceAsync(new RequestInfo(session, "Users", "Profile"), Global.CancellationTokenSource.Token).ConfigureAwait(false);
				account = (profile?.Get<string>("Name") ?? "Unknown") + $" ({session.User.ID})";
			}
			websocket.Set("ConnectionInfo",
				$"- Account: {account} - Session ID: {session.SessionID} - Device ID: {session.DeviceID} - Origin: {session.AppOrigin}" + "\r\n" +
				$"- App: {session.AppName} @ {session.AppPlatform} [{session.AppAgent}]" + "\r\n" +
				$"- Connection IP: {session.IP} - Location: {await session.GetLocationAsync(Global.GetCorrelationID(), Global.CancellationTokenSource.Token).ConfigureAwait(false)} - WebSocket: {websocket.ID} @ {websocket.RemoteEndPoint}"
			);
		}

		static string GetConnectionInfo(this ManagedWebSocket websocket)
			=> websocket.Get("ConnectionInfo", "");

		static async Task SendAsync(this ManagedWebSocket websocket, Exception exception, string msg = null, string correlationID = null)
		{
			// prepare
			correlationID = correlationID ?? Global.GetCorrelationID();
			var wampError = exception is WampException
				? (exception as WampException).GetDetails()
				: null;

			msg = msg ?? (wampError != null ? wampError.Item2 : exception.Message);
			var type = wampError != null ? wampError.Item3 : exception.GetType().GetTypeName(true);
			var code = wampError != null ? wampError.Item1 : exception.GetHttpStatusCode();

			var message = new JObject
			{
				{ "Message", msg },
				{ "Type", type },
				{ "Code", code },
				{ "CorrelationID", correlationID }
			};

			if (Global.IsDebugStacksEnabled)
			{
				if (wampError != null)
					message["Stack"] = wampError.Item4;

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

			message = new JObject
			{
				{ "Type", "Error" },
				{ "Data", message }
			};

			// send & write logs
			await Task.WhenAll(
				websocket.SendAsync(message.ToString(Formatting.None), true, Global.CancellationTokenSource.Token),
				Global.WriteLogsAsync(RTU.Logger, "RTU", msg ?? $"RTU error: {exception.Message}", exception, Global.ServiceName, LogLevel.Error, correlationID)
			).ConfigureAwait(false);
		}

		static Task SendAsync(this ManagedWebSocket websocket, UpdateMessage message)
			=> websocket.SendAsync(message.ToJson().ToString(Formatting.None), true, Global.CancellationTokenSource.Token);
	}
}