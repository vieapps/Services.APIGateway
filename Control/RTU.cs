#region Related components
using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Reactive.Subjects;
using System.Reactive.Linq;

using Newtonsoft.Json;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class RTUService : IRTUService
	{
		bool _updateEventLog = false;

		public RTUService()
		{
#if DEBUG || RUTLOGS
			this._updateEventLog = true;
#else
			this._updateEventLog = "true".IsEquals(UtilityService.GetAppSetting("Logs:RTU-EventLogs", "false"));
#endif
		}

		#region Send update messages
		ISubject<UpdateMessage> _updateSubject = null;

		void GetUpdateSubject()
		{
			this._updateSubject = this._updateSubject ?? Global.Component._outgoingChannel.RealmProxy.Services.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages");
		}

		public Task SendUpdateMessageAsync(UpdateMessage message, CancellationToken cancellationToken = default(CancellationToken))
		{
			if (message != null)
				try
				{
					this.GetUpdateSubject();
					this._updateSubject.OnNext(message);
					if (this._updateEventLog)
						Global.WriteLog(
							"----- [RTU Service] ---------------" + "\r\n" +
							"Publish an update message successful" + "\r\n" +
							"- Device: " + message.DeviceID + "\r\n" +
							"- Excluded: " + (string.IsNullOrWhiteSpace(message.ExcludedDeviceID) ? "None" : message.ExcludedDeviceID) + "\r\n" +
							"- Message: " + message.Data.ToString(Formatting.None) + "\r\n"
						);
				}
				catch (Exception ex)
				{
					Global.WriteLog("Error occurred while publishing an update message", ex);
				}
			return Task.CompletedTask;
		}

		public Task SendUpdateMessagesAsync(List<BaseMessage> messages, string deviceID, string excludedDeviceID, CancellationToken cancellationToken = default(CancellationToken))
		{
			if (messages != null && messages.Count > 0)
				try
				{
					this.GetUpdateSubject();
					using (var publisher = messages
						.Select(message => new UpdateMessage()
						{
							Type = message.Type,
							Data = message.Data,
							DeviceID = deviceID,
							ExcludedDeviceID = excludedDeviceID
						})
						.ToObservable()
						.Subscribe(
							message =>
							{
								this._updateSubject.OnNext(message);
								if (this._updateEventLog)
									Global.WriteLog(
										"----- [RTU Service] ---------------" + "\r\n" +
										"Publish an update message successful" + "\r\n" +
										"- Device: " + message.DeviceID + "\r\n" +
										"- Excluded: " + (string.IsNullOrWhiteSpace(message.ExcludedDeviceID) ? "None" : message.ExcludedDeviceID) + "\r\n" +
										"- Message: " + message.Data.ToString(Formatting.None) + "\r\n"
									);
							},
							exception => Global.WriteLog("Error occurred while publishing an update message", exception)
						)
					)
					{
						if (this._updateEventLog)
							Global.WriteLog(
								"----- [RTU Service] ---------------" + "\r\n" +
								"Publish the update messages successful" + "\r\n" +
								"- Device: " + deviceID + "\r\n" +
								"- Excluded: " + (string.IsNullOrWhiteSpace(excludedDeviceID) ? "None" : excludedDeviceID) + "\r\n" +
								"- Total of messages: " + messages.Count.ToString() + "\r\n"
							);
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
		Dictionary<string, ISubject<CommunicateMessage>> _communicateSubjects = new Dictionary<string, ISubject<CommunicateMessage>>();

		ISubject<CommunicateMessage> GetCommunicateSubject(string serviceName)
		{
			var uri = "net.vieapps.rtu.communicate.messages." + serviceName.Trim().ToLower();
			if (!this._communicateSubjects.TryGetValue(uri, out ISubject<CommunicateMessage> subject))
				lock (this._communicateSubjects)
				{
					if (!this._communicateSubjects.TryGetValue(uri, out subject))
					{
						subject = Global.Component._outgoingChannel.RealmProxy.Services.GetSubject<CommunicateMessage>(uri);
						this._communicateSubjects.Add(uri, subject);
					}
				}
			return subject;
		}

		public Task SendInterCommunicateMessageAsync(string serviceName, BaseMessage message, CancellationToken cancellationToken = default(CancellationToken))
		{
			return this.SendInterCommunicateMessageAsync(new CommunicateMessage(serviceName, message), cancellationToken);
		}

		public Task SendInterCommunicateMessageAsync(CommunicateMessage message, CancellationToken cancellationToken = default(CancellationToken))
		{
			if (message != null && !string.IsNullOrWhiteSpace(message.ServiceName))
				try
				{
					this.GetCommunicateSubject(message.ServiceName).OnNext(message);
					if (this._updateEventLog)
						Global.WriteLog(
							"----- [RTU Service] ---------------" + "\r\n" +
							"Publish an inter-communicate message successful" + "\r\n" +
							"- Message: " + message.Data.ToString(Formatting.None) + "\r\n"
						);
				}
				catch (Exception ex)
				{
					Global.WriteLog("Error occurred while publishing an inter-communicate message", ex);
				}
			return Task.CompletedTask;
		}

		public Task SendInterCommunicateMessagesAsync(string serviceName, List<BaseMessage> messages, CancellationToken cancellationToken = default(CancellationToken))
		{
			return !string.IsNullOrWhiteSpace(serviceName) && messages != null && messages.Count > 0
				? this.SendInterCommunicateMessagesAsync(serviceName, messages.Select(msg => new CommunicateMessage(serviceName, msg)).ToList())
				: Task.CompletedTask;
		}

		public Task SendInterCommunicateMessagesAsync(List<CommunicateMessage> messages, CancellationToken cancellationToken = default(CancellationToken))
		{
			var byServiceMessages = messages != null && messages.Count > 0
				? messages.ToLookup(m => m.ServiceName)
				: null;

			if (byServiceMessages != null)
				foreach (var msgs in byServiceMessages)
					this.SendInterCommunicateMessagesAsync(msgs.Key, msgs.ToList());

			return Task.CompletedTask;
		}

		Task SendInterCommunicateMessagesAsync(string serviceName, List<CommunicateMessage> messages)
		{
			if (messages != null && !string.IsNullOrWhiteSpace(serviceName))
				try
				{
					var subject = this.GetCommunicateSubject(serviceName);
					using (var publisher = messages
						.ToObservable()
						.Subscribe(
							message =>
							{
								subject.OnNext(message);
								if (this._updateEventLog)
									Global.WriteLog(
										"----- [RTU Service] ---------------" + "\r\n" +
										"Publish an inter-communicate message successful" + "\r\n" +
										"- Message: " + message.Data.ToString(Formatting.None) + "\r\n"
									);
							},
							exception => Global.WriteLog("Error occurred while publishing an inter-communicate message", exception)
						)
					)
					{
						if (this._updateEventLog)
							Global.WriteLog(
								"----- [RTU Service] ---------------" + "\r\n" +
								"Publish the inter-communicate messages successful" + "\r\n" +
								"- Destination: net.vieapps.services." + serviceName.ToLower() + "\r\n" +
								"- Total of messages: " + messages.Count.ToString() + "\r\n"
							);
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