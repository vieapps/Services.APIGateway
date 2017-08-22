#region Related components
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
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
						RTU._WaitingTimes = UtilityService.GetAppSetting("WaitingTimes", "234").CastAs<int>();
					}
					catch
					{
						RTU._WaitingTimes = 234;
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
			RTU.Updaters.ForEach(info => info.Value.Dispose());
		}
		#endregion

		internal static async Task ProcessRequestAsync(AspNetWebSocketContext context)
		{
			// prepare client credential
			ExpandoObject request = null;
			try
			{
				request = context.QueryString["request"] != null
					? context.QueryString["request"].Url64Decode().ToExpandoObject()
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
			var correlationID = Global.GetCorrelationID(context.Items);
			try
			{
				session.ParseJSONWebToken(appToken);
				if (!await InternalAPIs.CheckSessionAsync(session, correlationID))
					throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
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
			if (context.QueryString["restart"] != null)
				await Task.Delay(567);

			// fetch messages
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
			if (context.QueryString["restart"] != null)
				try
				{
					await context.SendAsync(new UpdateMessage() { Type = "Ping", DeviceID = session.DeviceID });
				}
				catch { }

			// register online session
			await session.RegisterOnlineAsync();

			// push messages to client's device
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

					await session.UnregisterOnlineAsync();

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

				// send messages
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

				// wait
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
		static async Task SendAsync(this AspNetWebSocketContext context, UpdateMessage message)
		{
			await context.SendAsync(message.ToJson().ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None));
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

		static Task RegisterOnlineAsync(this Session session)
		{
			return Task.CompletedTask;
		}

		static Task UnregisterOnlineAsync(this Session session)
		{
			return Task.CompletedTask;
		}

	}
}