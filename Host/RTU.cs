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

		#region Send update messages
		ISubject<UpdateMessage> _updateSubject = null;

		void GetUpdateSubject()
		{
			if (this._updateSubject == null)
				this._updateSubject = Global.Component._outgoingChannel.RealmProxy.Services.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages");
		}

		public Task SendUpdateMessageAsync(UpdateMessage message)
		{
			if (message != null)
				try
				{
					this.GetUpdateSubject();
					this._updateSubject.OnNext(message);
#if DEBUG
					Global.WriteLog(
						"Publish an update message successful" + "\r\n" +
						"- Device: " + message.DeviceID + "\r\n" +
						"- Excluded: " + (string.IsNullOrWhiteSpace(message.ExcludedDeviceID) ? "None" : message.ExcludedDeviceID) + "\r\n" +
						"- Message: " + message.Data.ToString(Formatting.None) + "\r\n"
					);
#endif
				}
				catch (Exception ex)
				{
					Global.WriteLog("Error occurred while publishing an update message", ex);
				}
			return Task.CompletedTask;
		}

		public Task SendUpdateMessagesAsync(List<BaseMessage> messages, string deviceID, string excludedDeviceID)
		{
			if (messages != null && messages.Count > 0)
				try
				{
					this.GetUpdateSubject();
					using (var publisher = messages
						.Select(msg => new UpdateMessage()
						{
							Type = msg.Type,
							Data = msg.Data,
							DeviceID = deviceID,
							ExcludedDeviceID = excludedDeviceID
						})
						.ToObservable()
						.Subscribe(
							message =>
							{
								this._updateSubject.OnNext(message);
#if DEBUG
								Global.WriteLog(
									"Publish an update message successful" + "\r\n" +
									"- Device: " + message.DeviceID + "\r\n" +
									"- Excluded: " + (string.IsNullOrWhiteSpace(message.ExcludedDeviceID) ? "None" : message.ExcludedDeviceID) + "\r\n" +
									"- Message: " + message.Data.ToString(Formatting.None) + "\r\n"
								);
#endif
							},
							exception =>
							{
								Global.WriteLog("Error occurred while publishing an update message", exception);
							}
						)
					)
					{
#if DEBUG
						Global.WriteLog(
							"Publish the update messages successful" + "\r\n" +
							"- Device: " + deviceID + "\r\n" +
							"- Excluded: " + (string.IsNullOrWhiteSpace(excludedDeviceID) ? "None" : excludedDeviceID) + "\r\n" +
							"- Total of messages: " + messages.Count.ToString() + "\r\n"
						);
#endif
					}
				}
				catch (Exception ex)
				{
					Global.WriteLog("Error occurred while publishing the update messages", ex);
				}
			return Task.CompletedTask;
		}
		#endregion

		#region Send inter-communicate messages
		Dictionary<string, ISubject<BaseMessage>> _communicateSubjects = new Dictionary<string, ISubject<BaseMessage>>();

		ISubject<BaseMessage> GetCommunicateSubject(string serviceName)
		{
			var uri = "net.vieapps.rtu.communicate.messages." + serviceName.ToLower();
			ISubject<BaseMessage> subject;
			if (!this._communicateSubjects.TryGetValue(uri, out subject))
				lock (this._communicateSubjects)
				{
					if (!this._communicateSubjects.TryGetValue(uri, out subject))
					{
						subject = Global.Component._outgoingChannel.RealmProxy.Services.GetSubject<BaseMessage>(uri);
						this._communicateSubjects.Add(uri, subject);
					}
				}
			return subject;
		}

		public Task SendInterCommunicateMessageAsync(string serviceName, BaseMessage message)
		{
			if (!string.IsNullOrWhiteSpace(serviceName) && message != null)
				try
				{
					var subject = this.GetCommunicateSubject(serviceName);
					subject.OnNext(message);
#if DEBUG
					Global.WriteLog(
						"Publish an inter-communicate message successful" + "\r\n" +
						"- Destination: net.vieapps.services." + serviceName.ToLower() + "\r\n" +
						"- Message: " + message.Data.ToString(Formatting.None) + "\r\n"
					);
#endif
				}
				catch (Exception ex)
				{
					Global.WriteLog("Error occurred while publishing an inter-communicate message", ex);
				}
			return Task.CompletedTask;
		}

		public Task SendInterCommunicateMessagesAsync(string serviceName, List<BaseMessage> messages)
		{
			if (!string.IsNullOrWhiteSpace(serviceName) && messages != null && messages.Count > 0)
				try
				{
					var subject = this.GetCommunicateSubject(serviceName);
					using (var publisher = messages
						.ToObservable()
						.Subscribe(
							message =>
							{
								subject.OnNext(message);
#if DEBUG
								Global.WriteLog(
									"Publish an inter-communicate message successful" + "\r\n" +
									"- Destination: net.vieapps.services." + serviceName.ToLower() + "\r\n" +
									"- Message: " + message.Data.ToString(Formatting.None) + "\r\n"
								);
#endif
							},
							exception =>
							{
								Global.WriteLog("Error occurred while publishing an inter-communicate message", exception);
							}
						)
					)
					{
#if DEBUG
						Global.WriteLog(
							"Publish the inter-communicate messages successful" + "\r\n" +
							"- Destination: net.vieapps.services." + serviceName.ToLower() + "\r\n" +
							"- Total of messages: " + messages.Count.ToString() + "\r\n"
						);
#endif
					}
				}
				catch (Exception ex)
				{
					Global.WriteLog("Error occurred while publishing the inter-communicate messages", ex);
				}
			return Task.CompletedTask;
		}
		#endregion

	}
}