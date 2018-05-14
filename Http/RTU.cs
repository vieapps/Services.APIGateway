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

		internal static void Initialize()
		{
			RTU.WebSocket = new Components.WebSockets.WebSocket(Logger.GetLoggerFactory(), null, Global.CancellationTokenSource.Token)
			{
				OnError = (websocket, exception) =>
				{
					Global.WriteLogsAsync("InternalAPIs", $"<RTU> {exception.Message}", exception);
				},
				OnConnectionEstablished = (websocket) =>
				{
					Task.Run(() => RTU.WhenConnectionEstablishedAsync(websocket)).ConfigureAwait(false);
				},
				OnConnectionBroken = (websocket) =>
				{
					Task.Run(() => RTU.WhenConnectionBrokenAsync(websocket)).ConfigureAwait(false);
				},
				OnMessageReceived = (websocket, result, data) =>
				{
					Task.Run(() => RTU.WhenMessageReceivedAsync(websocket, result, data)).ConfigureAwait(false);
				}
			};
			Global.Logger.LogInformation($"The {Global.ServiceName} WebSocket is started - Buffer size: {Components.WebSockets.WebSocket.ReceiveBufferSize:#,##0} bytes");
		}

		static async Task WhenConnectionEstablishedAsync(ManagedWebSocket websocket)
		{
			// prepare
			Session session = null;
			Dictionary<string, string> queryString = null;
			try
			{
				queryString = websocket.RequestUri.ParseQuery();

				if (!queryString.ContainsKey("x-request"))
				{
					await websocket.SendAsync(new InvalidRequestException("Request is not found")).ConfigureAwait(false);
					RTU.WebSocket.CloseWebSocket(websocket, WebSocketCloseStatus.InvalidPayloadData, "Request is not found");
					return;
				}

				ExpandoObject request;
				try
				{
					request = queryString["x-request"].Url64Decode().ToExpandoObject();
				}
				catch (Exception ex)
				{
					await websocket.SendAsync(new InvalidRequestException($"Request is invalid ({ex.Message})", ex)).ConfigureAwait(false);
					RTU.WebSocket.CloseWebSocket(websocket, WebSocketCloseStatus.InvalidPayloadData, $"Request is invalid ({ex.Message})");
					return;
				}

				var appToken = request.Get<string>("x-app-token");
				if (string.IsNullOrWhiteSpace(appToken))
				{
					await websocket.SendAsync(new TokenNotFoundException("Token is not found")).ConfigureAwait(false);
					RTU.WebSocket.CloseWebSocket(websocket);
					return;
				}

				websocket.Extra.TryGetValue("User-Agent", out object userAgent);
				websocket.Extra.TryGetValue("Referrer", out object urlReferrer);
				var ipAddress = $"{(websocket.RemoteEndPoint as IPEndPoint).Address}";

				session = Global.GetSession(queryString.ToNameValueCollection(), userAgent as string, ipAddress, new Uri(urlReferrer as string));
				session.DeviceID = request.Get("x-device-id", session.DeviceID);
				session.AppName = request.Get("x-app-name", session.AppName);
				session.AppPlatform = request.Get("x-app-platform", session.AppPlatform);

				if (string.IsNullOrWhiteSpace(session.DeviceID))
					throw new InvalidTokenException("Device identity is not found");

				// verify client credential
				await Global.UpdateWithAuthenticateTokenAsync(session, appToken).ConfigureAwait(false);
				if (!await Global.IsSessionExistAsync(session).ConfigureAwait(false))
					throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
			}
			catch (Exception ex)
			{
				await Global.WriteLogsAsync("InternalAPIs", $"<RTU> {ex.Message}", ex).ConfigureAwait(false);

				if (ex is TokenNotFoundException || ex is InvalidTokenException || ex is InvalidTokenSignatureException || ex is InvalidSessionException || ex is InvalidRequestException)
					await websocket.SendAsync(ex).ConfigureAwait(false);
				else
					await websocket.SendAsync(new InvalidRequestException($"Request is invalid ({ex.Message})", ex)).ConfigureAwait(false);
				RTU.WebSocket.CloseWebSocket(websocket, WebSocketCloseStatus.InvalidPayloadData, $"Request is invalid ({ex.Message})");
				return;
			}

			// wait for few times before connecting to WAMP router because Reactive.NET needs few times
			if (queryString.ContainsKey("x-restart"))
			{
				// send knock message
				await websocket.SendAsync(new UpdateMessage()
				{
					Type = "Knock"
				}).ConfigureAwait(false);

				// wait for a few times
				try
				{
					await Task.Delay(567, Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch
				{
					RTU.WebSocket.CloseWebSocket(websocket, WebSocketCloseStatus.InternalServerError);
					return;
				}
			}

			// register online session
			await Task.WhenAll(
				session.SendOnlineStatusAsync(true),
				Global.WriteLogsAsync("InternalAPIs",
					"<RTU> The real-time updater of a client's device is started" + "\r\n" +
					$"- Account: {(session.User.ID.Equals("") ? "Visitor" : session.User.ID)}" + "\r\n" +
					$"- Session: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
					$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]"
				)
			).ConfigureAwait(false);

			// push
			websocket.Extra["Session"] = session;
			websocket.Extra["Updater"] = WAMPConnections.IncommingChannel.RealmProxy.Services
					.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages")
					.Subscribe(
						async (message) =>
						{
							if (message.DeviceID.Equals("*") || message.DeviceID.IsEquals(session.DeviceID))
								try
								{
									await websocket.SendAsync(message).ConfigureAwait(false);
									if (Global.IsDebugLogEnabled)
										await Global.WriteLogsAsync("InternalAPIs",
											$"<RTU> Push the message to the subscriber's device successful" + "\r\n" +
											$"- Session: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
											$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
											$"- Message:\r\n{message.Data.ToString(Formatting.Indented)}"
										).ConfigureAwait(false);
								}
								catch (Exception ex)
								{
									await Global.WriteLogsAsync("InternalAPIs", $"<RTU> Error occurred while pushing message to the subscriber's device\r\n{message.ToJson().ToString(Formatting.None)}", ex).ConfigureAwait(false);
								}
						},
						exception => Global.WriteLogsAsync("InternalAPIs", "<RTU> Error occurred while fetching messages", exception).ConfigureAwait(false)
					);
		}

		static async Task WhenConnectionBrokenAsync(ManagedWebSocket websocket)
		{
			// prepare
			websocket.Extra.TryGetValue("Session", out object s);
			websocket.Extra.TryGetValue("Updater", out object updater);

			if (s == null || updater == null)
			{
				await Global.WriteLogsAsync("InternalAPIs", "<RTU> Close the connection (unknown reason)");
				if (updater != null)
					try
					{
						(updater as IDisposable).Dispose();
					}
					catch { }
				return;
			}

			var session = s as Session;
			try
			{
				(updater as IDisposable).Dispose();
			}
			catch (Exception ex)
			{
				await Global.WriteLogsAsync("InternalAPIs", $"<RTU> Error occurred while disposing updater: {session.ToJson().ToString(Formatting.None)}", ex).ConfigureAwait(false);
			}

			// update online status
			await Task.WhenAll(
				session.SendOnlineStatusAsync(false),
				Global.WriteLogsAsync("InternalAPIs",
					$"<RTU> The real-time updater of a client's device is stopped" + "\r\n" +
					$"- Account: {(session.User.ID.Equals("") ? "Visitor" : session.User.ID)}" + "\r\n" +
					$"- Session: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
					$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]"
				)
			).ConfigureAwait(false);
		}

		static async Task WhenMessageReceivedAsync(ManagedWebSocket websocket, WebSocketReceiveResult result, byte[] data)
		{
			// prepare information
			var requestInfo = (result.MessageType.Equals(WebSocketMessageType.Text) ? data.GetString() : "{}").ToExpandoObject();
			var serviceName = requestInfo.Get<string>("ServiceName");
			var objectName = requestInfo.Get<string>("ObjectName");
			var verb = (requestInfo.Get<string>("Verb") ?? "GET").ToUpper();
			var extra = requestInfo.Get<Dictionary<string, string>>("Extra");

			websocket.Extra.TryGetValue("Session", out object s);
			var session = s as Session;
			if (Global.IsDebugLogEnabled)
				await Global.WriteLogsAsync("InternalAPIs", $"<RTU> Begin request => {verb} /{serviceName ?? "unknown"}/{objectName ?? "unknown"}").ConfigureAwait(false);

			// refresh the session
			if ("PING".IsEquals(verb))
				await websocket.SendAsync(new UpdateMessage()
				{
					Type = "Pong",
					DeviceID = session.DeviceID
				}).ConfigureAwait(false);

			// update the session
			else if ("PATCH".IsEquals(verb) && "users".IsEquals(serviceName) && "session".IsEquals(objectName) && extra != null && extra.ContainsKey("x-session"))
			{
				var sessionInfo = (await Global.CurrentHttpContext.CallServiceAsync(new RequestInfo()
				{
					Session = new Session(session)
					{
						SessionID = extra["x-session"].Decrypt(Global.EncryptionKey.Reverse(), true)
					},
					ServiceName = "Users",
					ObjectName = "Session",
					Header = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "x-app-token", $"x-token-{extra["x-session"]}" }
					},
					Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "Signature", $"x-token-{extra["x-session"]}".GetHMACSHA256(Global.ValidationKey) }
					},
					CorrelationID = Global.GetCorrelationID()
				}).ConfigureAwait(false)).ToExpandoObject();

				// only patch when not expired
				if (DateTime.Parse(sessionInfo.Get<string>("ExpiredAt")) >= DateTime.Now)
				{
					session.SessionID = sessionInfo.Get<string>("ID");
					session.User.ID = sessionInfo.Get<string>("UserID");

					if (session.User.Equals(""))
						session.User = new User("", session.SessionID, new List<string> { SystemRole.All.ToString() }, new List<Privilege>());
					else
						session.User = sessionInfo.Get<string>("AccessToken").ParseAccessToken(Global.ECCKey);

					if (Global.IsDebugLogEnabled)
						await Global.WriteLogsAsync("InternalAPIs", $"<RTU> End request => Patch a session successful{(Global.IsDebugResultsEnabled ? "\r\n" + session.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None) : "")}").ConfigureAwait(false);
				}
			}

			// call service to process the request
			else if (!string.IsNullOrWhiteSpace(serviceName))
			{
				try
				{
					var stopwatch = Stopwatch.StartNew();

					var request = new RequestInfo(session, serviceName, objectName, verb, requestInfo.Get<Dictionary<string, string>>("Query"), requestInfo.Get<Dictionary<string, string>>("Header"), requestInfo.Get<string>("Body"), extra, Global.GetCorrelationID());
					if (serviceName.IsEquals("Users"))
						request.Extra["Signature"] = verb.IsEquals("POST") || verb.IsEquals("PUT")
							? request.Body.GetHMACSHA256(Global.ValidationKey)
							: (request.Header.ContainsKey("x-app-token") ? request.Header["x-app-token"] : $"x-token-{session.SessionID}").GetHMACSHA256(Global.ValidationKey);
					var json = await Global.CurrentHttpContext.CallServiceAsync(request).ConfigureAwait(false);

					// send the update message
					var @event = request.GetObjectIdentity();
					@event = !string.IsNullOrWhiteSpace(@event) && !@event.IsValidUUID()
						? @event
						: verb;
					await websocket.SendAsync(new UpdateMessage()
					{
						Type = serviceName.GetCapitalizedFirstLetter() + (string.IsNullOrWhiteSpace(objectName) ? "" : "#" + objectName.GetCapitalizedFirstLetter() + "#" + @event.GetCapitalizedFirstLetter()),
						DeviceID = session.DeviceID,
						Data = json
					}).ConfigureAwait(false);

					stopwatch.Stop();
					if (Global.IsDebugLogEnabled)
						await Global.WriteLogsAsync("InternalAPIs",
							$"<RTU> End request => Success" + "\r\n" +
							$"- Execution times: {stopwatch.GetElapsedTimes()}" + "\r\n" +
							$"- Session: {session.SessionID} @ {session.DeviceID}" + "\r\n" +
							$"- App Info: {session.AppName} @ {session.AppPlatform} - {session.AppOrigin} [IP: {session.IP} - Agent: {session.AppAgent}]" + "\r\n" +
							$"- Request:\r\n{requestInfo.ToJson().ToString(Formatting.Indented)}" + "\r\n" +
							$"- Response:\r\n{json.ToString(Formatting.Indented)}"
						).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					await Task.WhenAll(
						Global.WriteLogsAsync("InternalAPIs", $"<RTU> End request => Error occurred while processing request: {requestInfo?.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}", ex),
						websocket.SendAsync(ex, $"Error occurred while processing request: {requestInfo?.ToJson().ToString(Formatting.Indented)}")
					).ConfigureAwait(false);
				}
			}
		}

		static async Task SendAsync(this ManagedWebSocket websocket, Exception exception, string msg = null)
		{
			// prepare
			var wampError = exception is WampException
				? (exception as WampException).GetDetails()
				: null;

			msg = msg ?? (wampError != null ? wampError.Item2 : exception.Message);
			var type = wampError != null ? wampError.Item3 : exception.GetType().GetTypeName(true);

			var message = new JObject()
			{
				{ "Message", type },
				{ "Type", type },
				{ "CorrelationID", Global.GetCorrelationID() }
			};

			if (Global.IsDebugStacksEnabled)
			{
				if (wampError != null)
					message.Add(new JProperty("Stack", wampError.Item4));

				else
				{
					message.Add(new JProperty("Stack", exception.StackTrace));
					if (exception.InnerException != null)
					{
						var inners = new JArray();
						var counter = 1;
						var inner = exception.InnerException;
						while (inner != null)
						{
							inners.Add(new JObject()
							{
								{ "Error", "(" + counter + "): " + inner.Message + " [" + inner.GetType().ToString() + "]" },
								{ "Stack", inner.StackTrace }
							});
							counter++;
							inner = inner.InnerException;
						}
						message.Add(new JProperty("Inners", inners));
					}
				}
			}

			message = new JObject()
			{
				{ "Type", "Error" },
				{ "Data", message }
			};

			// send & write logs
			await Task.WhenAll(
				websocket.SendAsync(message.ToString(Global.IsDebugResultsEnabled ? Formatting.Indented : Formatting.None), true, Global.CancellationTokenSource.Token),
				Global.WriteLogsAsync("InternalAPIs", msg ?? "Error occurred while processing with real-time updater", exception)
			).ConfigureAwait(false);
		}

		static Task SendAsync(this ManagedWebSocket websocket, UpdateMessage message)
			=> websocket.SendAsync(message.ToJson().ToString(Global.IsDebugResultsEnabled ? Formatting.Indented : Formatting.None), true, Global.CancellationTokenSource.Token);
	}
}