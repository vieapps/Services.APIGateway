#region Related components
using System;
using System.Linq;
using System.Dynamic;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Web.WebSockets;
using System.Net.WebSockets;
using System.Reactive.Linq;
using System.Reactive.Subjects;

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
		internal static ISubject<UpdateMessage> Sender = null;
		internal static Dictionary<string, IDisposable> Updaters = new Dictionary<string, IDisposable>();

		internal static int _PushInterval = 0, _ProcessInterval = 0;

		internal static int PushInterval
		{
			get
			{
				if (RTU._PushInterval < 1)
					try
					{
						RTU._PushInterval = UtilityService.GetAppSetting("RTUPushInterval", "123").CastAs<int>();
					}
					catch
					{
						RTU._PushInterval = 123;
					}
				return RTU._PushInterval;
			}
		}

		internal static int ProcessInterval
		{
			get
			{
				if (RTU._ProcessInterval < 1)
					try
					{
						RTU._ProcessInterval = UtilityService.GetAppSetting("RTUProcessInterval", "13").CastAs<int>();
					}
					catch
					{
						RTU._ProcessInterval = 13;
					}
				return RTU._ProcessInterval;
			}
		}
		#endregion

		#region Updaters
		internal static IDisposable RegisterUpdater(string identity, Action<UpdateMessage> onNext, Action<Exception> onError)
		{
			identity = string.IsNullOrWhiteSpace(identity)
				? UtilityService.GetUUID()
				: identity;

			if (!RTU.Updaters.TryGetValue(identity, out IDisposable updater))
				lock (RTU.Updaters)
				{
					if (!RTU.Updaters.TryGetValue(identity, out updater))
					{
						updater = Global.IncommingChannel.RealmProxy.Services
							.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages")
							.Subscribe(onNext, onError);
						RTU.Updaters.Add(identity, updater);
					}
				}

			return updater;
		}

		internal static void UnregisterUpdater(string identity, bool remove = true)
		{
			if (!string.IsNullOrWhiteSpace(identity) && RTU.Updaters.ContainsKey(identity))
				try
				{
					RTU.Updaters[identity].Dispose();
					if (remove)
						RTU.Updaters.Remove(identity);
				}
				catch { }
		}

		internal static void StopUpdaters()
		{
			RTU.Updaters.ForEach(updater =>
			{
				try
				{
					updater.Dispose();
				}
				catch { }
			});
		}
		#endregion

		internal static async Task ProcessRequestAsync(AspNetWebSocketContext context)
		{
			// prepare
			Session session = null;
			try
			{
				// get app token
				var request = context.QueryString["x-request"]?.Url64Decode().ToExpandoObject() ?? new ExpandoObject();
				string appToken = request.Get<string>("x-app-token");
				if (string.IsNullOrWhiteSpace(appToken))
				{
					await context.SendAsync(new TokenNotFoundException("Token is not found"));
					return;
				}

				// prepare session
				session = Global.GetSession(context.Headers, context.QueryString, context.UserAgent, context.UserHostAddress, context.UrlReferrer);
				session.DeviceID = request.Get("x-device-id", session.DeviceID);
				session.AppName = request.Get("x-app-name", session.AppName);
				session.AppPlatform = request.Get("x-app-platform", session.AppPlatform);

				if (string.IsNullOrWhiteSpace(session.DeviceID))
					throw new InvalidTokenException("Device identity is not found");

				// verify client credential
				var accessToken = session.ParseJSONWebToken(appToken);
				if (!await InternalAPIs.CheckSessionExistAsync(session))
					throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
				await InternalAPIs.VerifySessionIntegrityAsync(session, accessToken);
			}
			catch (Exception ex)
			{
				if (ex is TokenNotFoundException || ex is InvalidTokenException || ex is InvalidTokenSignatureException || ex is InvalidSessionException)
					await context.SendAsync(ex);
				else
					await context.SendAsync(new InvalidTokenException("The token is invalid", ex));
				return;
			}

			// wait for few times before connecting to WAMP router because Reactive.NET needs times
			if (context.QueryString["x-restart"] != null)
				try
				{
					await Task.Delay(567, Global.CancellationTokenSource.Token);
				}
				catch
				{
					return;
				}

			// do the process
			if (session.SessionID.Encrypt(Global.AESKey.Reverse(), true).IsEquals(context.QueryString["x-receiver"]))
				await context.ProcesMessagesAsync(session);
			else
				await context.PushMessagesAsync(session);
		}

		#region Send messages via web socket
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
				{ "Type", exception.GetType().GetTypeName(true) },
				{ "Message", exception.Message },
				{ "CorrelationID", correlationID }
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

		#region Push messages to client devices
		static async Task PushMessagesAsync(this AspNetWebSocketContext context, Session session)
		{
			// fetch messages
			var correlationID = Global.GetCorrelationID(context.Items);
			var messages = new ConcurrentQueue<UpdateMessage>();
			try
			{
				RTU.RegisterUpdater(
					session.SessionID,
					(message) =>
					{
						messages.Enqueue(message);

#if DEBUG || RTULOGS
						Global.WriteLogs(correlationID, "RTU.Pusher", "Got an update message: " + message.ToJson().ToString(Formatting.None));
#endif
					},
					(ex) =>
					{
						Global.WriteLogs(correlationID, "RTU.Pusher", "Error occurred while fetching messages: " + ex.Message + " [" + ex.GetType().GetTypeName(true) + "]", ex);
					});
			}
			catch (Exception ex)
			{
				await context.SendAsync(new InvalidAppOperationException("Cannot start the subscriber of updating messages", ex));
				return;
			}

			// send knock message on re-start
			if (context.QueryString["x-restart"] != null)
				try
				{
					await context.SendAsync(new UpdateMessage()
					{
						Type = "Knock"
					});
				}
				catch { }

			// register online session
			await session.SendOnlineStatusAsync(true);

#if DEBUG || RTULOGS || REQUESTLOGS
			Global.WriteLogs(correlationID, "RTU.Pusher", new List<string>()
			{
				"The real-time updater of a client's device is started",
				"- Account: " + (session.User.ID.Equals("") ? "Visitor" : session.User.ID),
				"- Session: " + session.SessionID + " @ " + session.DeviceID,
				"- App Info: " + session.AppName + " @ " + session.AppPlatform  + " - " + session.AppOrigin + " [IP: " + session.IP + " - Agent: " + session.AppAgent + "]"
			});
#endif

			// do push
			while (true)
			{
				// stop when disconnected
				if (!context.WebSocket.State.Equals(WebSocketState.Open) || !context.IsClientConnected)
				{
					try
					{
						RTU.UnregisterUpdater(session.SessionID);
					}
					catch (Exception ex)
					{
						Global.WriteLogs(correlationID, "RTU.Pusher", "Error occurred while disposing subscriber: " + ex.Message + " [" + ex.GetType().GetTypeName(true) + "]", ex);
					}

					await session.SendOnlineStatusAsync(false);

#if DEBUG || RTULOGS || REQUESTLOGS
					await Global.WriteLogsAsync(correlationID, "RTU.Pusher", new List<string>()
					{
						"The real-time updater of a client's device is stopped",
						"- Account: " + (session.User.ID.Equals("") ? "Visitor" : session.User.ID),
						"- Session: " + session.SessionID + " @ " + session.DeviceID,
						"- App Info: " + session.AppName + " @ " + session.AppPlatform  + " - " + session.AppOrigin + " [IP: " + session.IP + " - Agent: " + session.AppAgent + "]"
					});
#endif
					return;
				}

				// push messages to client's device
				while (messages.Count > 0)
				{
					messages.TryDequeue(out UpdateMessage message);
					if (message != null && message.DeviceID.Equals("*") || message.DeviceID.IsEquals(session.DeviceID))
						try
						{
							await context.SendAsync(message);

#if DEBUG || RTULOGS
							await Global.WriteLogsAsync(correlationID, "RTU.Pusher", new List<string>()
							{
								"Push the message to the subscriber's device successful",
								"- Session: " + session.SessionID + " @ " + session.DeviceID,
								"- App Info: " + session.AppName + " @ " + session.AppPlatform  + " - " + session.AppOrigin + " [IP: " + session.IP + " - Agent: " + session.AppAgent + "]",
								"- Message: " + message.Data.ToString(Formatting.None)
							});
#endif
						}
						catch (OperationCanceledException)
						{
							return;
						}
						catch (Exception ex)
						{
							Global.WriteLogs(correlationID, "RTU.Pusher", new List<string>()
							{
								"Error occurred while pushing message to the subscriber's device",
								"- Message: " + message.ToJson().ToString(Formatting.None),
								"- Error: " + ex.Message + " [" + ex.GetType().GetTypeName(true) + "]"
							}, ex);
						}
				}

				// wait for next interval
				try
				{
					await Task.Delay(RTU.PushInterval, Global.CancellationTokenSource.Token);
				}
				catch (OperationCanceledException)
				{
					return;
				}
				catch (Exception) { }
			}
		}
		#endregion

		#region Process request messages that sent from client devices
		internal static void Publish(this UpdateMessage message)
		{
			if (RTU.Sender == null)
				Task.Run(async () =>
				{
					try
					{
						await Global.OpenOutgoingChannelAsync();
						RTU.Sender = Global.OutgoingChannel.RealmProxy.Services.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages");
						RTU.Sender.OnNext(message);
					}
					catch { }
				}).ConfigureAwait(false);

			else
				RTU.Sender.OnNext(message);
		}

		static async Task ProcesMessagesAsync(this AspNetWebSocketContext context, Session session)
		{
			while (true)
			{
				// stop when disconnected
				if (!context.WebSocket.State.Equals(WebSocketState.Open) || !context.IsClientConnected)
					return;

				// prepare the request
				var correlationID = Global.GetCorrelationID(context.Items);
				var requestMessage = "";
				try
				{
					// receive the request
					try
					{
						var buffer = new ArraySegment<byte>(new byte[4096]);
						var message = await context.WebSocket.ReceiveAsync(buffer, Global.CancellationTokenSource.Token);
						requestMessage = message.MessageType.Equals(WebSocketMessageType.Text)
							? buffer.Array.GetString(message.Count)
							: null;
					}
					catch (WebSocketException ex)
					{
						if (ex.Message.IsStartsWith("Reached the end of the file")
						|| ex.Message.IsStartsWith("The I/O operation has been aborted because of either a thread exit or an application request"))
							requestMessage = null;
						else
							throw ex;
					}
					catch (Exception)
					{
						throw;
					}

					var requestInfo = requestMessage?.ToExpandoObject();
					if (requestInfo == null)
						return;

					// prepare information
					var serviceName = requestInfo.Get<string>("ServiceName");
					var objectName = requestInfo.Get<string>("ObjectName");
					var verb = requestInfo.Get<string>("Verb") ?? "GET";
					var extra = requestInfo.Get<Dictionary<string, string>>("Extra");

					// update the session
					if ("PATCH".IsEquals(verb) && "users".IsEquals(serviceName) && "session".IsEquals(objectName) && extra != null && extra.ContainsKey("x-session"))
					{
						var sessionInfo = (await InternalAPIs.CallServiceAsync(new Session(session)
						{
							SessionID = extra["x-session"].Decrypt(Global.AESKey.Reverse(), true)
						}, "users", "session")).ToExpandoObject();

						session.SessionID = sessionInfo.Get<string>("ID");
						session.User.ID = sessionInfo.Get<string>("UserID");

						session.User = session.User.ID.Equals("")
							? new User() { Roles = new List<string>() { SystemRole.All.ToString() } }
							: (await InternalAPIs.CallServiceAsync(session, "users", "account")).FromJson<User>();

#if DEBUG || RTULOGS
						Global.WriteLogs(correlationID, "RTU.Processor", "Patch a session successful" + "\r\n" + session.ToJson().ToString(Formatting.Indented));
#endif
					}

					// call service to process the request
					else
					{
						// call the service
						var query = requestInfo.Get<Dictionary<string, string>>("Query");
						var data = await InternalAPIs.CallServiceAsync(new RequestInfo(session, serviceName, objectName, verb, query, requestInfo.Get<Dictionary<string, string>>("Header"), requestInfo.Get<string>("Body"), extra, correlationID));

						// send the update message
						var objectIdentity = query != null && query.ContainsKey("object-identity") ? query["object-identity"] : null;
						(new UpdateMessage()
						{
							Type = serviceName.GetCapitalizedFirstLetter() + "#" + objectName.GetCapitalizedFirstLetter() + (objectIdentity != null && !objectIdentity.IsValidUUID() ? "#" + objectIdentity.GetCapitalizedFirstLetter() : ""),
							DeviceID = session.DeviceID,
							Data = data
						}).Publish();

#if DEBUG || RTULOGS
						await Global.WriteLogsAsync(correlationID, "RTU.Processor", new List<string>()
						{
							"Process the client messages successful",
							"- Session: " + session.SessionID + " @ " + session.DeviceID,
							"- App Info: " + session.AppName + " @ " + session.AppPlatform  + " - " + session.AppOrigin + " [IP: " + session.IP + " - Agent: " + session.AppAgent + "]",
							"- Request: " + requestMessage ?? "None",
							"- Response: " + data.ToString(Formatting.None)
						});
#endif
					}
				}
				catch (OperationCanceledException)
				{
					return;
				}
				catch (Exception ex)
				{
					Global.WriteLogs(correlationID, "RTU.Processor", new List<string>()
					{
						"Error occurred while processing the client messages",
						"- Session: " + session.SessionID + " @ " + session.DeviceID,
						"- App Info: " + session.AppName + " @ " + session.AppPlatform  + " - " + session.AppOrigin + " [IP: " + session.IP + " - Agent: " + session.AppAgent + "]",
						"- Request: " + requestMessage ?? "None",
						"- Error: " + ex.Message + " [" + ex.GetType().GetTypeName(true) + "]"
					}, ex);
				}

				// wait for next interval
				try
				{
					await Task.Delay(RTU.ProcessInterval, Global.CancellationTokenSource.Token);
				}
				catch (OperationCanceledException)
				{
					return;
				}
				catch (Exception) { }
			}
		}
		#endregion

	}
}