#region Related components
using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;

using System.Reactive.Subjects;
using System.Reactive.Linq;

#if DEBUG
using Newtonsoft.Json;
#endif
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class RTUService : IRTUService
	{
		public RTUService() { }

		ISubject<UpdateMessage> _subject = null;

		void GetSubject()
		{
			if (this._subject == null)
				this._subject = Global.Component._outgoingChannel.RealmProxy.Services.GetSubject<UpdateMessage>("net.vieapps.rtu.client.messages");
		}

		public Task SendUpdateMessageAsync(UpdateMessage message)
		{
			if (message != null)
				try
				{
					this.GetSubject();
					this._subject.OnNext(message);
#if DEBUG
					Global.WriteLog(
						"Publish a client's message successful" + "\r\n" +
						"- Device: " + message.DeviceID + "\r\n" +
						"- Excluded: " + (string.IsNullOrWhiteSpace(message.ExcludedDeviceID) ? "None" : message.ExcludedDeviceID) + "\r\n" +
						"- Message: " + message.Data.ToString(Formatting.None) + "\r\n"
					);
#endif
				}
				catch (Exception ex)
				{
					Global.WriteLog("Error occurred while publishing a client's message", ex);
				}
			return Task.CompletedTask;
		}

		public Task SendUpdateMessagesAsync(List<BaseMessage> messages, string deviceID, string excludedDeviceID)
		{
			if (messages != null && messages.Count > 0)
				try
				{
					this.GetSubject();
					var publisher = messages
						.Select(msg => new UpdateMessage()
						{
							Type = msg.Type,
							Data = msg.Data,
							DeviceID = deviceID,
							ExcludedDeviceID = excludedDeviceID
						})
						.ToObservable()
						.Subscribe(
							(message) =>
							{
								this._subject.OnNext(message);
#if DEBUG
								Global.WriteLog(
									"Publish a client's message successful" + "\r\n" +
									"- Device: " + message.DeviceID + "\r\n" +
									"- Excluded: " + (string.IsNullOrWhiteSpace(message.ExcludedDeviceID) ? "None" : message.ExcludedDeviceID) + "\r\n" +
									"- Message: " + message.Data.ToString(Formatting.None) + "\r\n"
								);
#endif
							},
							(exception) =>
							{
								Global.WriteLog("Error occurred while publishing a client's message", exception);
							}
						);
					publisher.Dispose();
				}
				catch (Exception ex)
				{
					Global.WriteLog("Error occurred while publishing the clients' messages", ex);
				}
			return Task.CompletedTask;
		}

		Dictionary<string, ISubject<BaseMessage>> _subjects = new Dictionary<string, ISubject<BaseMessage>>();

		ISubject<BaseMessage> GetSubject(string serviceName)
		{
			var uri = "net.vieapps.rtu.service.messages." + serviceName.ToLower();
			ISubject<BaseMessage> subject;
			if (!this._subjects.TryGetValue(uri, out subject))
				lock (this._subjects)
				{
					if (!this._subjects.TryGetValue(uri, out subject))
					{
						subject = Global.Component._outgoingChannel.RealmProxy.Services.GetSubject<BaseMessage>(uri);
						this._subjects.Add(uri, subject);
					}
				}
			return subject;
		}

		public Task SendInterCommuniateMessageAsync(string serviceName, BaseMessage message)
		{
			if (!string.IsNullOrWhiteSpace(serviceName) && message != null)
				try
				{
					var subject = this.GetSubject(serviceName);
					subject.OnNext(message);
#if DEBUG
					Global.WriteLog(
						"Publish a service's message successful" + "\r\n" +
						"- Destination: net.vieapps.services." + serviceName.ToLower() + "\r\n" +
						"- Message: " + message.Data.ToString(Formatting.None) + "\r\n"
					);
#endif
				}
				catch (Exception ex)
				{
					Global.WriteLog("Error occurred while publishing a service's message", ex);
				}
			return Task.CompletedTask;
		}

		public Task SendInterCommuniateMessagesAsync(string serviceName, List<BaseMessage> messages)
		{
			if (!string.IsNullOrWhiteSpace(serviceName) && messages != null && messages.Count > 0)
				try
				{
					var subject = this.GetSubject(serviceName);
					var publisher = messages
						.ToObservable()
						.Subscribe(
							(message) =>
							{
								subject.OnNext(message);
#if DEBUG
								Global.WriteLog(
									"Publish a service's message successful" + "\r\n" +
									"- Destination: net.vieapps.services." + serviceName.ToLower() + "\r\n" +
									"- Message: " + message.Data.ToString(Formatting.None) + "\r\n"
								);
#endif
							},
							(exception) =>
							{
								Global.WriteLog("Error occurred while publishing a service's message", exception);
							}
						);
					publisher.Dispose();
				}
				catch (Exception ex)
				{
					Global.WriteLog("Error occurred while publishing the services' messages", ex);
				}
			return Task.CompletedTask;
		}
	}
}