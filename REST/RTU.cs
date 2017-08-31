#region Related components
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using System.Text;
using System.Dynamic;
using System.Web.WebSockets;
using System.Net.WebSockets;

using System.Reactive.Linq;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class RTU
	{

		#region Attributes
		internal static Dictionary<string, IDisposable> Updaters = new Dictionary<string, IDisposable>();

		internal static int _WaitingTimes = 0;
		internal static int WaitingTimes
		{
			get
			{
				if (RTU._WaitingTimes < 1)
					try
					{
						RTU._WaitingTimes = UtilityService.GetAppSetting("WaitingTimes", "123").CastAs<int>();
					}
					catch
					{
						RTU._WaitingTimes = 123;
					}
				return RTU._WaitingTimes;
			}
		}
		#endregion

		#region Updaters
		internal static IDisposable RegisterUpdater(string identity, Action<UpdateMessage> onNext, Action<Exception> onError)
		{
			identity = string.IsNullOrWhiteSpace(identity)
				? UtilityService.GetUUID()
				: identity;

			var subject = Global.IncommingChannel?.RealmProxy.Services.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages");
			if (subject == null)
				throw new InvalidAppOperationException("Cannot initialize the subject for fetching messages");

			if (!RTU.Updaters.TryGetValue(identity, out IDisposable updater))
				lock (RTU.Updaters)
				{
					if (!RTU.Updaters.TryGetValue(identity, out updater))
					{
						updater = subject.Subscribe(onNext, onError);
						RTU.Updaters.Add(identity, updater);
					}
				}

			return updater;
		}

		internal static void UnregisterUpdater(string identity, bool remove = true)
		{
			if (!string.IsNullOrWhiteSpace(identity) && RTU.Updaters.ContainsKey(identity))
			{
				RTU.Updaters[identity].Dispose();
				if (remove)
					RTU.Updaters.Remove(identity);
			}
		}

		internal static void StopUpdaters()
		{
			RTU.Updaters.ForEach(updater => updater.Dispose());
		}
		#endregion

		internal static async Task ProcessRequestAsync(AspNetWebSocketContext context)
		{
			// prepare client credential
			ExpandoObject request = null;
			try
			{
				request = context.QueryString["x-request"] != null
					? context.QueryString["x-request"].Url64Decode().ToExpandoObject()
					: new ExpandoObject();
			}
			catch (Exception ex)
			{
				await context.SendAsync(new TokenNotFoundException("Token is not found", ex));
				return;
			}

			string appToken = request.Get<string>("x-app-token");
			if (string.IsNullOrWhiteSpace(appToken))
			{
				await context.SendAsync(new TokenNotFoundException("Token is not found"));
				return;
			}

			var session = Global.GetSession(context.Headers, context.QueryString, context.UserAgent, context.UserHostAddress, context.UrlReferrer);
			if (request.Has("x-device-id"))
				session.DeviceID = request.Get<string>("x-device-id");
			if (request.Has("x-app-name"))
				session.AppName = request.Get<string>("x-app-name");
			if (request.Has("x-app-platform"))
				session.AppPlatform = request.Get<string>("x-app-platform");

			if (string.IsNullOrWhiteSpace(session.DeviceID))
			{
				await context.SendAsync(new InvalidTokenException("Device identity is not found"));
				return;
			}

			// prepare client credential
			try
			{
				var accessToken = session.ParseJSONWebToken(appToken);
				if (!await InternalAPIs.CheckSessionExistAsync(session))
					throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
				await InternalAPIs.VerifySessionIntegrityAsync(session, accessToken);
			}
			catch (Exception ex)
			{
				await context.SendAsync(ex);
				return;
			}

			// connect to the router
			try
			{
				await Global.OpenIncomingChannelAsync();
			}
			catch (Exception ex)
			{
				await context.SendAsync(new InvalidAppOperationException("Cannot open the channel of the real-time updater for fetching messages", ex));
				return;
			}

			// wait for few seconds before connecting to WAMP router because Reactive.NET needs few times
			if (context.QueryString["x-restart"] != null)
				await Task.Delay(567);

			// fetch messages
			var correlationID = Global.GetCorrelationID(context.Items);
			var messages = new Queue<UpdateMessage>();
			try
			{
				RTU.RegisterUpdater(
						session.SessionID,
						message => messages.Enqueue(message),
						ex => Global.WriteLogs(correlationID, "RTU", "Error occurred while fetching messages", ex)
					);

#if DEBUG || RTULOGS
				Global.WriteLogs(correlationID, "RTU", new List<string>() {
					"The real-time updater of a client's device is started",
					"- Account: " + (session.User.ID.Equals("") ? "Visitor" : session.User.ID),
					"- Session: " + session.SessionID + " @ " + session.DeviceID,
					"- Info: " + session.AppName + " / " + session.AppPlatform  + " - " + session.AppOrigin + " [IP: " + session.IP + " - Agent: " + session.AppAgent + "]"
				});
#endif
			}
			catch (Exception ex)
			{
				await context.SendAsync(new InvalidAppOperationException("Cannot start the subscriber for fetching messages", ex));
				return;
			}

			// ping message on re-start
			if (context.QueryString["x-restart"] != null)
				try
				{
					await context.SendAsync(new UpdateMessage() { Type = "Ping", DeviceID = session.DeviceID });
				}
				catch { }

			// register online session
			await session.SendOnlineStatusAsync(true);

			// do the process
			while (true)
			{
				// client is disconnected
				if (!context.WebSocket.State.Equals(WebSocketState.Open) || !context.IsClientConnected)
				{
					try
					{
						RTU.UnregisterUpdater(session.SessionID);
					}
					catch (Exception ex)
					{
						Global.WriteLogs(correlationID, "RTU", "Error occurred while disposing subscriber: " + ex.Message, ex);
					}

					await session.SendOnlineStatusAsync(false);

#if DEBUG || RTULOGS
					Global.WriteLogs(correlationID, "RTU", new List<string>() {
							"The real-time updater of a client's device is stopped",
							"- Account: " + (session.User.ID.Equals("") ? "Visitor" : session.User.ID),
							"- Session: " + session.SessionID + " @ " + session.DeviceID,
							"- Info: " + session.AppName + " / " + session.AppPlatform  + " - " + session.AppOrigin + " [IP: " + session.IP + " - Agent: " + session.AppAgent + "]"
						});
#endif
					break;
				}

				// push messages to client's device
				while (messages.Count > 0)
					try
					{
						var message = messages.Dequeue();
						if (message.DeviceID.Equals("*") || message.DeviceID.IsEquals(session.DeviceID))
						{
							await context.SendAsync(message);
#if DEBUG || RTULOGS
							Global.WriteLogs(correlationID, "RTU", new List<string>() {
								"Push the message to the subscriber's device successful",
								"- Session: " + session.SessionID,
								"- Device: " + session.DeviceID + " @ " + session.AppName + " / " + session.AppPlatform + " [IP: " + session.IP + "]",
								"- Message: " + message.Data.ToString(Formatting.None)
							});
#endif
						}
					}
					catch (Exception ex)
					{
						Global.WriteLogs(correlationID, "RTU", "Error occurred while pushing message to the subscriber's device", ex);
					}

				// process the request that sent from client (receive request  & call service)
				await context.ProcessClientRequestAsync(session);

				// wait for next cycle
				try
				{
					await Task.Delay(RTU.WaitingTimes, Global.CancellationTokenSource.Token);
				}
				catch (OperationCanceledException)
				{
					break;
				}
				catch (Exception) { }
			}
		}

		#region Send messages
		static async Task SendAsync(this AspNetWebSocketContext context, UpdateMessage message, string verb = null)
		{
			// prepare the message
			var json = message.ToJson() as JObject;
			json.Add(new JProperty("Status", "OK"));
			if (!string.IsNullOrWhiteSpace(verb))
				json.Add(new JProperty("Verb", verb));

			// send the message
			await context.SendAsync(json.ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None));
		}

		static async Task SendAsync(this AspNetWebSocketContext context, Exception exception)
		{
			// prepare
			var correlationID = Global.GetCorrelationID(context.Items);
			var message = new JObject()
			{
				{ "Message", exception.Message },
				{ "CorrelationID", correlationID },
				{ "Type", exception.GetType().ToString().ToArray('.').Last() },
			};

			if (Global.IsShowErrorStacks)
			{
				message.Add(new JProperty("Stack", exception.StackTrace));
				if (exception.InnerException != null)
				{
					var inners = new JArray();
					var counter = 0;
					var inner = exception.InnerException;
					while (inner != null)
					{
						counter++;
						inners.Add(new JObject()
						{
							{ "Error", "(" + counter + "): " + inner.Message + " [" + inner.GetType().ToString() + "]" },
							{ "Stack", inner.StackTrace }
						});
						inner = inner.InnerException;
					}
					message.Add(new JProperty("Inners", inners));
				}
			}

			message = new JObject()
			{
				{ "Type", "Error" },
				{ "Status", "Error" },
				{ "Data", message }
			};

			// send & write logs
			await Task.WhenAll(
					context.SendAsync(message.ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None)),
					Global.WriteLogsAsync(correlationID, "RTU", "Error occurred while processing with real-time updater: " + exception.Message, exception)
				);
		}

		static async Task SendAsync(this AspNetWebSocketContext context, string message)
		{
			if (context.WebSocket.State.Equals(WebSocketState.Open))
				try
				{
					await context.WebSocket.SendAsync(new ArraySegment<byte>(message.ToBytes()), WebSocketMessageType.Text, true, Global.CancellationTokenSource.Token);
				}
				catch (OperationCanceledException) { }
				catch (Exception ex)
				{
					await Global.WriteLogsAsync(Global.GetCorrelationID(context.Items), "RTU", "Error occurred while sending message via WebSocket: " + ex.Message, ex);
				}
		}
		#endregion

		#region Receive request & call services
		static async Task ProcessClientRequestAsync(this AspNetWebSocketContext context, Session session)
		{
			var correlationID = UtilityService.GetUUID();
			try
			{
				// receive message from client
				var buffer = new ArraySegment<byte>(new byte[1024]);
				var message = await context.WebSocket.ReceiveAsync(buffer, Global.CancellationTokenSource.Token);

				if (!message.MessageType.Equals(WebSocketMessageType.Text))
					return;

				// parse request and process
				var request = buffer.Array.GetString(message.Count).ToExpandoObject();
				if (request != null)
				{
					var verb = request.Get<string>("Verb") ?? "GET";

					// update session
					if ("PATCH".IsEquals(verb) && !session.User.ID.Equals("") && !session.User.ID.Equals(User.SystemAccountID))
						try
						{
							var updatedSession = (await InternalAPIs.GetSessionAsync(session)).ToExpandoObject();
							if (session.SessionID.Equals(updatedSession.Get<string>("SessionID")) && session.User.ID.Equals(updatedSession.Get<string>("UserID")))
							{
								session.User.ID = updatedSession.Get<string>("UserID");
								session.User = (await InternalAPIs.CallServiceAsync(session, "users", "account")).FromJson<User>();
							}
						}
						catch { }

					// call service
					else
					{
						// parse the request
						var requestInfo = new RequestInfo(session)
						{
							ServiceName = request.Get<string>("ServiceName") ?? "unknown",
							ObjectName = request.Get<string>("ObjectName") ?? "unknown",
							Verb = verb,
							Query = request.Get<Dictionary<string, string>>("Query"),
							Header = request.Get<Dictionary<string, string>>("Header"),
							Body = request.Get<string>("Body"),
							Extra = request.Get<Dictionary<string, string>>("Header"),
							CorrelationID = correlationID
						};

						// call the service
						var data = await InternalAPIs.CallServiceAsync(requestInfo);

						// send the update message
						await context.SendAsync(new UpdateMessage()
						{
							Type = requestInfo.ServiceName.GetCapitalizedFirstLetter() + "#" + requestInfo.ObjectName.GetCapitalizedFirstLetter(),
							DeviceID = session.DeviceID,
							Data = data
						}, verb);
					}
				}
			}
			catch (OperationCanceledException) { }
			catch (Exception ex)
			{
				await Global.WriteLogsAsync(correlationID, "RTU", "Error occurred while calling a service with real-time updater: " + ex.Message, ex);
			}
		}
		#endregion

	}
}