﻿#region Related components
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Reactive.Linq;

using WampSharp.V2.Realm;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class Manager : IManager, IDisposable
	{
		/// <summary>
		/// Creates new instance of services manager
		/// </summary>
		public Manager()
		{
			this.OnIncomingChannelEstablished = (sender, args) =>
			{
				Task.Run(async () =>
				{
					if (this.Instance != null)
						await this.Instance.DisposeAsync().ConfigureAwait(false);
					this.Instance = await WAMPConnections.IncomingChannel.RealmProxy.Services.RegisterCallee(this, RegistrationInterceptor.Create()).ConfigureAwait(false);
				})
				.ContinueWith(task =>
				{
					this.Communicator?.Dispose();
					this.Communicator = WAMPConnections.IncomingChannel.RealmProxy.Services
						.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages.apigateway")
						.Subscribe(
							message => this.ProcessInterCommunicateMessageAsync(message),
							exception => Global.OnError?.Invoke($"Error occurred while fetching inter-communicate message: {exception.Message}", exception)
						);
				}, TaskContinuationOptions.OnlyOnRanToCompletion)
				.ConfigureAwait(false);
			};

			this.OnOutgoingChannelEstablished = (sender, args) => Task.Run(async () =>
			{
				while (WAMPConnections.IncomingChannel == null || WAMPConnections.OutgoingChannel == null)
					await Task.Delay(UtilityService.GetRandomNumber(123, 456)).ConfigureAwait(false);
				this.RTUService = WAMPConnections.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<IRTUService>(ProxyInterceptor.Create());
				await this.SendRequestInfoAsync().ConfigureAwait(false);
				Global.OnProcess?.Invoke($"Successfully subscribe the manager's communicator");
			}).ConfigureAwait(false);

			var interval = UtilityService.GetAppSetting("RequestTimer:Interval", "15").CastAs<int>();
			this.RequestTimer = Observable.Timer(TimeSpan.FromMinutes(interval), TimeSpan.FromMinutes(interval)).Subscribe(_ => Task.Run(() => this.SendRequestInfoAsync()).ConfigureAwait(false));
		}

		public void Dispose()
		{
			if (!this.Disposed)
				Task.Run(async () =>
				{
					this.Disposed = true;
					if (this.Instance != null)
						await this.Instance.DisposeAsync().ConfigureAwait(false);
				})
				.ContinueWith(task =>
				{
					this.Communicator?.Dispose();
					this.RequestTimer?.Dispose();
				}, TaskContinuationOptions.OnlyOnRanToCompletion)
				.ConfigureAwait(false);
		}

		~Manager() => this.Dispose();

		#region Properties
		ConcurrentDictionary<string, ControllerInfo> Controllers { get; } = new ConcurrentDictionary<string, ControllerInfo>();
		ConcurrentDictionary<string, IController> ServiceManagers { get; } = new ConcurrentDictionary<string, IController>();
		ConcurrentDictionary<string, List<ServiceInfo>> Services { get; } = new ConcurrentDictionary<string, List<ServiceInfo>>();
		SystemEx.IAsyncDisposable Instance { get; set; } = null;
		IDisposable Communicator { get; set; } = null;
		IRTUService RTUService { get; set; } = null;
		IDisposable RequestTimer { get; set; } = null;
		bool Disposed { get; set; } = false;
		public IDictionary<string, ControllerInfo> AvailableControllers => this.Controllers as IDictionary<string, ControllerInfo>;
		public IDictionary<string, List<ServiceInfo>> AvailableServices => this.Services as IDictionary<string, List<ServiceInfo>>;
		#endregion

		#region Event handlers
		public Action<object, WampSessionCreatedEventArgs> OnIncomingChannelEstablished { get; }

		public Action<object, WampSessionCreatedEventArgs> OnOutgoingChannelEstablished { get; }

		public Action<CommunicateMessage> OnInterCommunicateMessageReceived { get; set; }

		public Action<string, string> OnServiceStarted { get; set; }

		public Action<string, string> OnServiceStopped { get; set; }
		#endregion

		#region Process business services
		internal IController GetServiceManager(string controllerID)
		{
			if (!this.ServiceManagers.TryGetValue(controllerID, out IController serviceManager))
			{
				serviceManager = WAMPConnections.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<IController>(ProxyInterceptor.Create(controllerID));
				this.ServiceManagers.TryAdd(controllerID, serviceManager);
			}
			return serviceManager;
		}

		bool IsBusinessServiceAvailable(string controllerID, string name)
		{
			if (this.Services.TryGetValue(name, out List<ServiceInfo> services))
			{
				var svcInfo = services.FirstOrDefault(svc => svc.ControllerID.Equals(controllerID) && svc.Name.Equals(name));
				return svcInfo != null && svcInfo.Available;
			}
			return false;
		}

		public void StartBusinessService(string controllerID, string name, string arguments)
		{
			try
			{
				if (this.IsBusinessServiceAvailable(controllerID, name))
					this.GetServiceManager(controllerID)?.StartBusinessService(name, arguments);
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke($"Error occurred while starting a business service: {ex.Message}", ex);
			}
		}

		public void StopBusinessService(string controllerID, string name)
		{
			try
			{
				if (this.IsBusinessServiceAvailable(controllerID, name))
					this.GetServiceManager(controllerID)?.StopBusinessService(name);
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke($"Error occurred while stopping a business service: {ex.Message}", ex);
			}
		}
		#endregion

		#region Process inter-communicate messages
		public async Task SendInterCommunicateMessageAsync(string type, JToken data = null)
		{
			if (this.RTUService != null)
				try
				{
					await this.RTUService.SendInterCommunicateMessageAsync(new CommunicateMessage
					{
						ServiceName = "APIGateway",
						Type = type,
						Data = data ?? new JObject()
					}).ConfigureAwait(false);
				}
				catch { }
		}

		void ProcessInterCommunicateMessageAsync(CommunicateMessage message)
		{
			// controller info
			if (message.Type.IsStartsWith("Controller#"))
			{
				ControllerInfo controller = null;
				switch (message.Type.ToArray('#').Last().ToLower())
				{
					case "info":
					case "connect":
						if (this.Controllers.TryGetValue(message.Data.Get<string>("ID"), out controller))
							controller.CopyFrom(message.Data, "ID".ToHashSet());
						else
						{
							controller = message.Data.FromJson<ControllerInfo>();
							this.Controllers.TryAdd(controller.ID, controller);
						}
						break;

					case "disconnect":
						controller = message.Data.FromJson<ControllerInfo>();
						if (this.Controllers.TryGetValue(controller.ID, out controller))
						{
							controller.Available = false;
							controller.Timestamp = DateTime.Now;
							this.Services.ForEach(kvp =>
							{
								var svcInfo = kvp.Value.FirstOrDefault(svc => svc.Name.Equals(kvp.Key) && svc.ControllerID.Equals(controller.ID));
								if (svcInfo != null)
									svcInfo.Available = svcInfo.Running = false;
							});
						}
						break;
				}
			}

			// service info
			else if (message.Type.IsEquals("Service#Info"))
			{
				var serviceInfo = message.Data.FromJson<ServiceInfo>();

				if (!this.Services.TryGetValue(serviceInfo.Name.ToLower(), out List<ServiceInfo> services))
				{
					services = new List<ServiceInfo>();
					this.Services.TryAdd(serviceInfo.Name.ToLower(), services);
				}

				var svcInfo = services.FirstOrDefault(svc => svc.Name.Equals(serviceInfo.Name) && svc.UniqueName.Equals(serviceInfo.UniqueName) && svc.ControllerID.Equals(serviceInfo.ControllerID));
				if (svcInfo == null)
					services.Add(serviceInfo);
				else
				{
					if (svcInfo.Available != serviceInfo.Available || svcInfo.Running != serviceInfo.Running)
						svcInfo.Timestamp = DateTime.Now;
					svcInfo.Available = serviceInfo.Available;
					svcInfo.Running = serviceInfo.Running;
					if (svcInfo.Running)
						svcInfo.InvokeInfo = serviceInfo.InvokeInfo;
				}

				if (serviceInfo.Running)
					this.OnServiceStarted?.Invoke(serviceInfo.ControllerID, serviceInfo.Name);
				else
					this.OnServiceStopped?.Invoke(serviceInfo.ControllerID, serviceInfo.Name);
			}

			// registered handler
			this.OnInterCommunicateMessageReceived?.Invoke(message);
		}
		#endregion

		#region Get available controllers & services
		public JArray GetAvailableControllers()
		{
			var controllers = new JArray();
			this.Controllers.Values.ToList().ForEach(controller => controllers.Add(new JObject
			{
				{ "ID", controller.ID.GenerateUUID() },
				{ "Platform", controller.Platform },
				{ "Available" , controller.Available }
			}));
			return controllers;
		}

		public JArray GetAvailableServices()
		{
			var services = new JArray();
			this.Services.Values.ToList().ForEach(service => services.Add(new JObject
			{
				{ "URI", $"net.vieapps.services.{service[0].Name}" },
				{ "Available", service.FirstOrDefault(svc => svc.Available) != null },
				{ "Running", service.FirstOrDefault(svc => svc.Running) != null }
			}));
			return services;
		}
		#endregion

		Task SendRequestInfoAsync()
			=> Task.WhenAll(this.SendInterCommunicateMessageAsync("Controller#RequestInfo"), this.SendInterCommunicateMessageAsync("Service#RequestInfo"));
	}

	// ------------------------------------------------------------

	[Serializable]
	public class ControllerInfo
	{
		public ControllerInfo() { }
		public string ID { get; set; }
		public string User { get; set; }
		public string Host { get; set; }
		public string Platform { get; set; }
		public string Mode { get; set; }
		public bool Available { get; set; } = false;
		public DateTime Timestamp { get; set; } = DateTime.Now;
		public Dictionary<string, string> Extra { get; set; }
	}

	// ------------------------------------------------------------

	[Serializable]
	public class ServiceInfo
	{
		public ServiceInfo() { }
		public string Name { get; set; }
		public string UniqueName { get; set; }
		public string ControllerID { get; set; }
		public string InvokeInfo { get; set; }
		public DateTime Timestamp { get; set; } = DateTime.Now;
		public bool Available { get; set; } = false;
		public bool Running { get; set; } = false;
	}
}