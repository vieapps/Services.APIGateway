#region Related components
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using System.Web.WebSockets;
using System.Net.WebSockets;

using System.Reactive.Subjects;
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
		internal static CancellationTokenSource CancellationTokenSource = new CancellationTokenSource();
		internal static Dictionary<string, IDisposable> Subscribers = new Dictionary<string, IDisposable>();

		#region Subscribers
		internal static ISubject<UpdateMessage> GetSubject()
		{
			return Global.OutgoingChannel?.RealmProxy.Services.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages");
		}

		internal static IDisposable RegisterSubscriber(string identity, ISubject<UpdateMessage> subject, Action<UpdateMessage> onNext, Action<Exception> onError = null)
		{
			identity = string.IsNullOrWhiteSpace(identity)
				? UtilityService.GetUUID()
				: identity;

			if (!RTU.Subscribers.TryGetValue(identity, out IDisposable subscriber))
				lock (RTU.Subscribers)
				{
					if (!RTU.Subscribers.TryGetValue(identity, out subscriber))
					{
						subscriber = subject.Subscribe(onNext, onError);
						RTU.Subscribers.Add(identity, subscriber);
					}
				}

			return subscriber;
		}

		internal static void UnregisterSubscriber(string identity, bool remove = true)
		{
			if (!string.IsNullOrWhiteSpace(identity) && RTU.Subscribers.ContainsKey(identity))
			{
				RTU.Subscribers[identity].Dispose();
				if (remove)
					RTU.Subscribers.Remove(identity);
			}
		}

		internal static void StopSubscribers()
		{
			RTU.Subscribers.ForEach(info =>
			{
				info.Value.Dispose();
			});
		}
		#endregion

		internal static async Task ProcessRequestAsync(AspNetWebSocketContext context)
		{
			// validate client credential
			string appToken = null;
			try
			{
				appToken = context.QueryString["x-app-token"];
				if (string.IsNullOrWhiteSpace(appToken))
					throw new TokenNotFoundException();
			}
			catch (Exception ex)
			{
				await context.SendAsync(ex);
				return;
			}

			var session = Global.GetSession(context.Headers, context.QueryString, context.UserHostAddress, context.UrlReferrer, context.UserAgent);
			if (string.IsNullOrWhiteSpace(session.DeviceID))
			{
				await context.SendAsync(new InvalidTokenException("Device identity is not found"));
				return;
			}

			// parse JSON Web Token and check access token
			try
			{
				await session.ParseJSONWebTokenAsync(appToken, InternalAPIs.CheckSessionAsync);
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

			// prepare subject to fetch message from WAMP router
			ISubject<UpdateMessage> subject = null;
			try
			{
				subject = RTU.GetSubject();
				if (subject == null)
					throw new InvalidAppOperationException("Cannot initialize the subject for fetching messages");
			}
			catch (Exception ex)
			{
				await context.SendAsync(ex);
				return;
			}

			// fetch messages
			var correlationID = Global.GetCorrelationID(context.Items);
			var messages = new Queue<UpdateMessage>();
			try
			{
				RTU.RegisterSubscriber(session.SessionID, subject, message => messages.Enqueue(message));

#if DEBUG || RTULOGS
				Global.WriteLogs(correlationID, "RTU", new List<string>() {
					"The real-time updater of a client's device is started",
					"- Account: " + (session.User.ID.Equals("") ? "Visitor" : session.User.ID),
					"- Session ID: " + session.SessionID,
					"- Device ID: " + session.DeviceID,
					"- IP: " + session.IP,
					"- App: " + session.AppName + "/" + session.AppPlatform,
					"- Origin: " + session.AppOrigin,
					"- Agent: " + session.AppAgent + "\r\n",
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
			await session.RegisterOnlineAsync(session.IP);

			// push messages to client's device
			while (true)
			{
				// client is disconnected
				if (!context.WebSocket.State.Equals(WebSocketState.Open) || !context.IsClientConnected)
				{
					try
					{
						RTU.UnregisterSubscriber(session.SessionID);
					}
					catch (Exception ex)
					{
						Global.WriteLogs(correlationID, "RTU", "Error occurred while disposing subscriber: " + ex.Message, ex);
					}

					await session.UnregisterOnlineAsync(session.IP);

#if DEBUG || RTULOGS
					Global.WriteLogs(correlationID, "RTU", new List<string>() {
							"The real-time updater of a client's device is stopped",
							"- Account: " + (session.User.ID.Equals("") ? "Visitor" : session.User.ID),
							"- Session ID: " + session.SessionID,
							"- Device ID: " + session.DeviceID,
							"- IP: " + session.IP,
							"- App: " + session.AppName + "/" + session.AppPlatform,
							"- Origin: " + session.AppOrigin,
							"- Agent: " + session.AppAgent + "\r\n",
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
								"- Session: " + (session.User.ID.Equals("") ? "Visitor" : session.User.ID) + " @ " + session.SessionID,
								"- Device: " + session.DeviceID + " @ " + session.AppName + "/" + session.AppPlatform + " [IP: " + session.IP + "]",
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
					await Task.Delay(234, RTU.CancellationTokenSource.Token);
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
					await context.WebSocket.SendAsync(new ArraySegment<byte>(message.ToBytes()), WebSocketMessageType.Text, true, RTU.CancellationTokenSource.Token);
				}
				catch (OperationCanceledException) { }
				catch (Exception ex)
				{
					await Global.WriteLogsAsync(Global.GetCorrelationID(context.Items), "RTU", "Error occurred while sending message via WebSocket: " + ex.Message, ex);
				}
		}
		#endregion

		#region Register/Unregister online sessions
		static Task RegisterOnlineAsync(this Session session, string ipAddress = null)
		{
			return Task.CompletedTask;
		}

		static Task UnregisterOnlineAsync(this Session session, string ipAddress = null)
		{
			return Task.CompletedTask;
		}
		#endregion

	}
}