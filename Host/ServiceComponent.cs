﻿#region Related components
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Configuration;

using WampSharp.V2;
using WampSharp.V2.Core.Contracts;
using WampSharp.V2.Realm;
using WampSharp.Core.Listener;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal class ServiceComponent : IDisposable
	{

		#region Attributes
		internal IWampChannel _incommingChannel = null, _outgoingChannel = null;
		long _incommingChannelSessionID = 0, _outgoingChannelSessionID = 0;
		bool _channelsAreClosedBySystem = false;

		ManagementService _managementService = null;
		internal List<string> _availableServices = null;
		internal Dictionary<string, int> _runningServices = new Dictionary<string, int>();
		#endregion

		#region Constructor & Destructor
		public ServiceComponent() { }

		~ServiceComponent()
		{
			this.Dispose();
		}

		public void Dispose()
		{
			this.Stop();
		}
		#endregion

		#region Start/Stop
		internal void Start(string[] args = null, Action nextAction = null, Func<Task> nextActionAsync = null)
		{
			Task.Run(async () =>
			{
				await this.StartAsync(args);
			})
			.ContinueWith(async (task) =>
			{
				try
				{
					nextAction?.Invoke();
				}
				catch (Exception ex)
				{
					Global.WriteLog("Error occurred while running the next action (sync)", ex);
				}
				if (nextActionAsync != null)
					try
					{
						await nextActionAsync().ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						Global.WriteLog("Error occurred while running the next action (async)", ex);
					}
			})
			.ConfigureAwait(false);
		}

		internal async Task StartAsync(string[] args = null)
		{
			// open channels
			Global.WriteLog("Starting the API Gateway..." + "\r\n");
			await this.OpenIncomingChannelAsync(
				(sender, arguments) =>
				{
					Global.WriteLog("The incoming connection is established - Session ID: " + arguments.SessionId + "\r\n");
					this._incommingChannelSessionID = arguments.SessionId;
				},
				(sender, arguments) =>
				{
					if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
						Global.WriteLog("The incoming connection is broken because the router is not found or the router is refused - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString() + "\r\n");
					else
					{
						if (this._channelsAreClosedBySystem)
							Global.WriteLog("The incoming connection is closed - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString() + "\r\n");
						else
							this.ReOpenIncomingChannel(
								123,
								() =>
								{
									Global.WriteLog("Re-connect the incoming connection successful");
								},
								ex =>
								{
									Global.WriteLog("Error occurred while re-connecting the incoming connection", ex);
								}
							);
					}
				},
				(sender, arguments) =>
				{
					Global.WriteLog("Got an error of incoming connection: " + (arguments.Exception != null ? arguments.Exception.Message : "None"), arguments.Exception);
				}
			);

			await this.OpenOutgoingChannelAsync(
				(sender, arguments) =>
				{
					Global.WriteLog("The outgoing connection is established - Session ID: " + arguments.SessionId + "\r\n");
					this._outgoingChannelSessionID = arguments.SessionId;
				},
				(sender, arguments) =>
				{
					if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
						Global.WriteLog("The outgoing connection is broken because the router is not found or the router is refused - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString());
					else
					{
						if (this._channelsAreClosedBySystem)
							Global.WriteLog("The outgoing connection is closed - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString() + "\r\n");
						else
							this.ReOpenOutgoingChannel(
								123,
								() =>
								{
									Global.WriteLog("Re-connect the outgoing connection successful");
								},
								ex =>
								{
									Global.WriteLog("Error occurred while re-connecting the outgoing connection", ex);
								}
							);
					}
				},
				(sender, arguments) =>
				{
					Global.WriteLog("Got an error of incoming connection: " + (arguments.Exception != null ? arguments.Exception.Message : "None"), arguments.Exception);
				}
			);

			// register services
			await this.RegisterServicesAsync(args);
		}

		internal void Stop()
		{
			this._managementService?.FlushAll();

			this._runningServices.ForEach(info =>
			{
				this.StopService(info.Key, false, false);
			});
			this._runningServices.Clear();
			this.UpdateServicesInfo();

			this._channelsAreClosedBySystem = true;
			this.CloseIncomingChannel();
			this.CloseOutgoingChannel();
		}
		#endregion

		#region Open/Close channels
		protected virtual Tuple<string, string, bool> GetLocationInfo()
		{
			var address = UtilityService.GetAppSetting("RouterAddress", "ws://127.0.0.1:26429/");
			var realm = UtilityService.GetAppSetting("RouterRealm", "VIEAppsRealm");
			var mode = UtilityService.GetAppSetting("RouterChannelsMode", "MsgPack");
			return new Tuple<string, string, bool>(address, realm, mode.IsEquals("json"));
		}

		public async Task OpenIncomingChannelAsync(Action<object, WampSessionCreatedEventArgs> onConnectionEstablished = null, Action<object, WampSessionCloseEventArgs> onConnectionBroken = null, Action<object, WampConnectionErrorEventArgs> onConnectionError = null)
		{
			if (this._incommingChannel != null)
				return;

			var info = this.GetLocationInfo();
			var address = info.Item1;
			var realm = info.Item2;
			var useJsonChannel = info.Item3;

			this._incommingChannel = useJsonChannel
				? (new DefaultWampChannelFactory()).CreateJsonChannel(address, realm)
				: (new DefaultWampChannelFactory()).CreateMsgpackChannel(address, realm);

			if (onConnectionEstablished != null)
				this._incommingChannel.RealmProxy.Monitor.ConnectionEstablished += new EventHandler<WampSessionCreatedEventArgs>(onConnectionEstablished);

			if (onConnectionBroken != null)
				this._incommingChannel.RealmProxy.Monitor.ConnectionBroken += new EventHandler<WampSessionCloseEventArgs>(onConnectionBroken);

			if (onConnectionError != null)
				this._incommingChannel.RealmProxy.Monitor.ConnectionError += new EventHandler<WampConnectionErrorEventArgs>(onConnectionError);

			await this._incommingChannel.Open();
		}

		public void CloseIncomingChannel()
		{
			if (this._incommingChannel != null)
			{
				this._incommingChannel.Close("The incoming channel is closed when stop the API Gateway Hosting Service", new GoodbyeDetails());
				this._incommingChannel = null;
			}
		}

		protected void ReOpenIncomingChannel(int delay = 0, Action onSuccess = null, Action<Exception> onError = null)
		{
			if (this._incommingChannel != null)
				(new WampChannelReconnector(this._incommingChannel, async () =>
				{
					await Task.Delay(delay > 0 ? delay : 0);
					try
					{
						await this._incommingChannel.Open();
						onSuccess?.Invoke();
					}
					catch (Exception ex)
					{
						onError?.Invoke(ex);
					}
				})).Start();
		}

		public async Task OpenOutgoingChannelAsync(Action<object, WampSessionCreatedEventArgs> onConnectionEstablished = null, Action<object, WampSessionCloseEventArgs> onConnectionBroken = null, Action<object, WampConnectionErrorEventArgs> onConnectionError = null)
		{
			if (this._outgoingChannel != null)
				return;

			var info = this.GetLocationInfo();
			var address = info.Item1;
			var realm = info.Item2;
			var useJsonChannel = info.Item3;

			this._outgoingChannel = useJsonChannel
				? (new DefaultWampChannelFactory()).CreateJsonChannel(address, realm)
				: (new DefaultWampChannelFactory()).CreateMsgpackChannel(address, realm);

			if (onConnectionEstablished != null)
				this._outgoingChannel.RealmProxy.Monitor.ConnectionEstablished += new EventHandler<WampSessionCreatedEventArgs>(onConnectionEstablished);

			if (onConnectionBroken != null)
				this._outgoingChannel.RealmProxy.Monitor.ConnectionBroken += new EventHandler<WampSessionCloseEventArgs>(onConnectionBroken);

			if (onConnectionError != null)
				this._outgoingChannel.RealmProxy.Monitor.ConnectionError += new EventHandler<WampConnectionErrorEventArgs>(onConnectionError);

			await this._outgoingChannel.Open();
		}

		public void CloseOutgoingChannel()
		{
			if (this._outgoingChannel != null)
			{
				this._outgoingChannel.Close("The outgoing channel is closed when stop the API Gateway Hosting Service", new GoodbyeDetails());
				this._outgoingChannel = null;
			}
		}

		protected void ReOpenOutgoingChannel(int delay = 0, Action onSuccess = null, Action<Exception> onError = null)
		{
			if (this._outgoingChannel != null)
				(new WampChannelReconnector(this._outgoingChannel, async () =>
				{
					await Task.Delay(delay > 0 ? delay : 0);
					try
					{
						await this._outgoingChannel.Open();
						onSuccess?.Invoke();
					}
					catch (Exception ex)
					{
						onError?.Invoke(ex);
					}
				})).Start();
		}
		#endregion

		#region Register & update info of services
		internal async Task RegisterServicesAsync(string[] args = null)
		{
			// register helper services
			var registerHelperServices = true;
			if (args != null && args.Length > 0)
				for (var index = 0; index < args.Length; index++)
					if (args[index].IsStartsWith("/helper-services:"))
					{
						if (args[index].IsEndsWith(":false"))
							registerHelperServices = false;
						break;
					}

			if (registerHelperServices)
			{
				this._managementService = new ManagementService();
				await this._incommingChannel.RealmProxy.Services.RegisterCallee(this._managementService, new CalleeRegistrationInterceptor(new RegisterOptions() { Invoke = WampInvokePolicy.Roundrobin }));
				Global.WriteLog("The management service is registered" + "\r\n");

				await this._incommingChannel.RealmProxy.Services.RegisterCallee(new RTUService(), new CalleeRegistrationInterceptor(new RegisterOptions() { Invoke = WampInvokePolicy.Roundrobin }));
				Global.WriteLog("The real-time update (RTU) service is registered" + "\r\n");
			}

			// register services
			if (this._availableServices == null)
				this.GetAvailableServices();

			this._availableServices.ForEach(name =>
			{
				this.StartService(name);
			});

			this.UpdateServicesInfo();
		}

		internal void UpdateServicesInfo()
		{
			if (!Global.AsService)
				Global.Form.UpdateServicesInfo(this._availableServices.Count, this._runningServices.Count);
		}

		internal void GetAvailableServices()
		{
			var current = Process.GetCurrentProcess().ProcessName + ".exe";
			this._availableServices = UtilityService.GetFiles(Directory.GetCurrentDirectory(), "*.exe")
				.Where(info => !info.Name.IsEquals(current))
				.Select(info => info.Name)
				.ToList();
		}
		#endregion

		#region Start/Stop service
		internal void StartService(string name, string arguments = null)
		{
			if (string.IsNullOrWhiteSpace(name) || this._runningServices.ContainsKey(name.ToLower()))
				return;

			var process = UtilityService.RunProcess(
				name,
				arguments,
				(sender, args) =>
				{
					this._runningServices.Remove((sender as Process).StartInfo.FileName);
					try
					{
						Global.WriteLog(
							"----- [" + (sender as Process).StartInfo.FileName + " - PID: " + (sender as Process).Id.ToString() + "] ------------------" + "\r\n" +
							"The sevice is stopped..." + "\r\n" +
							"--------------------------------------------------------------------------------" + "\r\n"
						);
					}
					catch { }
				},
				(sender, args) =>
				{
					if (!string.IsNullOrWhiteSpace(args.Data))
						try
						{
							Global.WriteLog(
								"----- [" + (sender as Process).StartInfo.FileName + " - PID: " + (sender as Process).Id.ToString() + "] ------------------" + "\r\n" +
								args.Data + "\r\n" +
								"--------------------------------------------------------------------------------" + "\r\n"
							);
						}
						catch { }
				}
			);

			this._runningServices.Add(name.ToLower(), process.Id);
			Global.WriteLog("The service [" + name + " - PID: " + process.Id.ToString() + "] is running...");
		}

		internal void StopService(int processId)
		{
			UtilityService.KillProcess(processId);
		}

		internal void StopService(string name, bool clean = true, bool updateInfo = true)
		{
			if (!string.IsNullOrWhiteSpace(name) && this._runningServices.ContainsKey(name.ToLower()))
			{
				this.StopService(this._runningServices[name.ToLower()]);
				if (clean)
					this._runningServices.Remove(name.ToLower());
				if (updateInfo)
					this.UpdateServicesInfo();
			}
		}
		#endregion

	}
}
