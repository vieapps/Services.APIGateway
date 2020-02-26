#region Related components
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Reactive.Subjects;
using System.Reactive.Linq;
using Newtonsoft.Json;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class RTUService : IRTUService
	{
		ISubject<UpdateMessage> UpdateMessagePublisher { get; set; } = null;

		public ISubject<UpdateMessage> GetUpdateMessagePublisher()
			=> this.UpdateMessagePublisher ?? (this.UpdateMessagePublisher = Router.OutgoingChannel.RealmProxy.Services.GetSubject<UpdateMessage>("messages.update"));

		public Task SendUpdateMessageAsync(UpdateMessage message, CancellationToken cancellationToken = default)
			=> UtilityService.ExecuteTask(() =>
			{
				try
				{
					this.GetUpdateMessagePublisher().OnNext(message);
					Global.OnSendRTUMessageSuccess?.Invoke(
						$"Publish an update message successful" + "\r\n" +
						$"- Device: {message.DeviceID}" + "\r\n" +
						$"- Excluded: {(string.IsNullOrWhiteSpace(message.ExcludedDeviceID) ? "None" : message.ExcludedDeviceID)}" + "\r\n" +
						$"- Type: {message.Type}" + "\r\n" +
						$"- Data: {message.Data.ToString(Formatting.None)}"
					);
				}
				catch (Exception exception)
				{
					Global.OnSendRTUMessageFailure?.Invoke($"Error occurred while publishing an update message: {exception.Message}", exception);
				}
			}, cancellationToken);

		public Task SendUpdateMessagesAsync(List<BaseMessage> messages, string deviceID, string excludedDeviceID, CancellationToken cancellationToken = default)
			=> UtilityService.ExecuteTask(() =>
			{
				using (var publisher = messages.Select(message => new UpdateMessage
				{
					Type = message.Type,
					Data = message.Data,
					DeviceID = deviceID,
					ExcludedDeviceID = excludedDeviceID
				}).ToObservable().Subscribe(
					message =>
					{
						this.GetUpdateMessagePublisher().OnNext(message);
						Global.OnSendRTUMessageSuccess?.Invoke(
							$"Publish an update message successful" + "\r\n" +
							$"- Device: {message.DeviceID}" + "\r\n" +
							$"- Excluded: {(string.IsNullOrWhiteSpace(message.ExcludedDeviceID) ? "None" : message.ExcludedDeviceID)}" + "\r\n" +
							$"- Type: {message.Type}" + "\r\n" +
							$"- Data: {message.Data.ToString(Formatting.None)}"
						);
					},
					exception => Global.OnSendRTUMessageFailure?.Invoke($"Error occurred while publishing an update message: {exception.Message}", exception)
				)) { }
			}, cancellationToken);

		ConcurrentDictionary<string, ISubject<CommunicateMessage>> InterCommunicateMessagePublishers { get; } = new ConcurrentDictionary<string, ISubject<CommunicateMessage>>();

		public ISubject<CommunicateMessage> GetInterCommunicateMessagePublisher(string serviceName)
		{
			var uri = "messages.services." + serviceName.Trim().ToLower();
			if (!this.InterCommunicateMessagePublishers.TryGetValue(uri, out var subject))
			{
				subject = Router.OutgoingChannel.RealmProxy.Services.GetSubject<CommunicateMessage>(uri);
				this.InterCommunicateMessagePublishers.TryAdd(uri, subject);
			}
			return subject;
		}

		public Task SendInterCommunicateMessageAsync(string serviceName, BaseMessage message, CancellationToken cancellationToken = default)
			=> this.SendInterCommunicateMessageAsync(new CommunicateMessage(serviceName, message), cancellationToken);

		public Task SendInterCommunicateMessageAsync(CommunicateMessage message, CancellationToken cancellationToken = default)
			=> UtilityService.ExecuteTask(() =>
			{
				if (message != null && !string.IsNullOrWhiteSpace(message.ServiceName))
					try
					{
						this.GetInterCommunicateMessagePublisher(message.ServiceName).OnNext(message);
						Global.OnSendRTUMessageSuccess?.Invoke(
							$"Publish an inter-communicate message successful" + "\r\n" +
							$"- Service: {message.ServiceName}" + "\r\n" +
							$"- Type: {message.Type}" + "\r\n" +
							$"- Data: {message.Data.ToString(Formatting.None)}"
						);
					}
					catch (Exception exception)
					{
						Global.OnSendRTUMessageFailure?.Invoke($"Error occurred while publishing an inter-communicate message: {exception.Message}", exception);
					}
			}, cancellationToken);

		public Task SendInterCommunicateMessagesAsync(string serviceName, List<BaseMessage> messages, CancellationToken cancellationToken = default)
			=> !string.IsNullOrWhiteSpace(serviceName) && messages != null && messages.Count > 0
				? this.SendInterCommunicateMessagesAsync(serviceName, messages.Select(msg => new CommunicateMessage(serviceName, msg)).ToList(), cancellationToken)
				: Task.CompletedTask;

		public Task SendInterCommunicateMessagesAsync(List<CommunicateMessage> messages, CancellationToken cancellationToken = default)
		{
			var byServiceMessages = messages != null && messages.Count > 0
				? messages.ToLookup(m => m.ServiceName)
				: null;

			return Task.WhenAll(
				byServiceMessages != null
					? byServiceMessages.Select(msgs => this.SendInterCommunicateMessagesAsync(msgs.Key, msgs.ToList(), cancellationToken))
					: new List<Task>()
			);
		}

		Task SendInterCommunicateMessagesAsync(string serviceName, List<CommunicateMessage> messages, CancellationToken cancellationToken = default)
			=> UtilityService.ExecuteTask(() =>
			{
				if (messages != null && !string.IsNullOrWhiteSpace(serviceName))
				{
					var subject = this.GetInterCommunicateMessagePublisher(serviceName);
					using (var publisher = messages.ToObservable().Subscribe(
						message =>
						{
							subject.OnNext(message);
							Global.OnSendRTUMessageSuccess?.Invoke(
								$"Publish an inter-communicate message successful" + "\r\n" +
								$"- Service: {message.ServiceName}" + "\r\n" +
								$"- Type: {message.Type}" + "\r\n" +
								$"- Data: {message.Data.ToString(Formatting.None)}"
							);
						},
						exception => Global.OnSendRTUMessageFailure?.Invoke($"Error occurred while publishing an inter-communicate message: {exception.Message}", exception)
					)) { }
				}
			}, cancellationToken);
	}
}