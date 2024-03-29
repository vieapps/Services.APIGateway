﻿#region Related components
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Reactive.Linq;
using WampSharp.V2.Realm;
using WampSharp.V2.Core.Contracts;
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
			this.OnIncomingConnectionEstablished = async (sender, args) =>
			{
				try
				{
					try
					{
						await (this.Instance != null ? this.Instance.DisposeAsync().AsTask() : Task.CompletedTask).ConfigureAwait(false);
					}
					catch { }
					this.Instance = await Router.IncomingChannel.RealmProxy.Services.RegisterCallee<IManager>(() => this, RegistrationInterceptor.Create()).ConfigureAwait(false);

					this.Communicator?.Dispose();
					this.Communicator = Router.IncomingChannel.RealmProxy.Services
						.GetSubject<CommunicateMessage>("messages.services.apigateway")
						.Subscribe
						(
							message => this.ProcessInterCommunicateMessage(message),
							exception => Global.OnError?.Invoke($"Error occurred while fetching inter-communicate message => {exception.Message}", exception)
						);
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Error occurred while initializing the manager => {ex.Message}", ex);
				}
			};

			this.OnOutgoingConnectionEstablished = async (sender, args) =>
			{
				try
				{
					while (Router.IncomingChannel == null || Router.OutgoingChannel == null)
						await Task.Delay(UtilityService.GetRandomNumber(123, 456)).ConfigureAwait(false);
					await this.SendRequestInfoAsync().ConfigureAwait(false);
					Global.OnProcess?.Invoke($"Successfully subscribe the manager's communicator");
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Error occurred while sending the request info => {ex.Message}", ex);
				}
			};

			this.RequestInfoInterval = Int32.TryParse(UtilityService.GetAppSetting("TimerInterval:RequestInfo"), out var requestInterval) ? requestInterval : 15;
			this.RequestInfoTimer = Observable.Timer(TimeSpan.FromMinutes(this.RequestInfoInterval), TimeSpan.FromMinutes(this.RequestInfoInterval)).Subscribe(async _ =>
			{
				if ((DateTime.Now - this.RequestTime).TotalMinutes >= this.RequestInfoInterval - 2)
				{
					try
					{
						await this.SendRequestInfoAsync().ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						Global.OnError?.Invoke($"Error occurred while sending the request info => {ex.Message}", ex);
					}
					this.RequestTime = DateTime.Now;
				}
			});
		}

		public async Task DisposeAsync()
		{
			if (!this.Disposed)
			{
				this.Disposed = true;
				if (this.Instance != null)
					try
					{
						await this.Instance.DisposeAsync().ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						Global.OnError?.Invoke($"Error occurred while disposing the manager => {ex.Message}", ex);
					}
					finally
					{
						this.Instance = null;
					}
				this.Communicator?.Dispose();
				this.RequestInfoTimer?.Dispose();
				Global.OnProcess?.Invoke($"The API Gateway Manager was disposed");
				await Task.Delay(123).ConfigureAwait(false);
			}
		}

		public void Dispose()
		{
			GC.SuppressFinalize(this);
			this.DisposeAsync().Run(true);
		}

		~Manager()
			=> this.Dispose();

		#region Properties
		ConcurrentDictionary<string, ControllerInfo> Controllers { get; } = new ConcurrentDictionary<string, ControllerInfo>();

		ConcurrentDictionary<string, IController> ServiceManagers { get; } = new ConcurrentDictionary<string, IController>();

		ConcurrentDictionary<string, List<ServiceInfo>> Services { get; } = new ConcurrentDictionary<string, List<ServiceInfo>>();

		IAsyncDisposable Instance { get; set; }

		IDisposable Communicator { get; set; }

		IDisposable RequestInfoTimer { get; set; }

		int RequestInfoInterval { get; set; }

		DateTime RequestTime { get; set; } = DateTime.Now;

		bool Disposed { get; set; } = false;

		public IDictionary<string, ControllerInfo> AvailableControllers => this.Controllers as IDictionary<string, ControllerInfo>;

		public IDictionary<string, List<ServiceInfo>> AvailableServices => this.Services as IDictionary<string, List<ServiceInfo>>;
		#endregion

		#region Event handlers
		public Action<object, WampSessionCreatedEventArgs> OnIncomingConnectionEstablished { get; }

		public Action<object, WampSessionCreatedEventArgs> OnOutgoingConnectionEstablished { get; }

		public Action<CommunicateMessage> OnInterCommunicateMessageReceived { get; set; }

		public Action<string, string> OnServiceStarted { get; set; }

		public Action<string, string> OnServiceStopped { get; set; }
		#endregion

		#region Process business services
		internal IController GetServiceManager(string controllerID)
		{
			if (!this.ServiceManagers.TryGetValue(controllerID, out IController serviceManager))
			{
				serviceManager = Router.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<IController>(ProxyInterceptor.Create(controllerID));
				this.ServiceManagers.TryAdd(controllerID, serviceManager);
			}
			return serviceManager;
		}

		bool IsBusinessServiceAvailable(string controllerID, string name)
		{
			if (this.Services.TryGetValue(name, out var services))
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

		#region Get available controllers & services
		public JArray GetAvailableControllers()
			=> this.Controllers.Values.Select(controller => new JObject
			{
				{ "ID", controller.ID.GenerateUUID() },
				{ "Platform", controller.Platform },
				{ "Available" , controller.Available }
			}).ToJArray();

		public JArray GetAvailableServices()
			=> this.Services.Values.Select(services => new JObject
			{
				{ "URI", $"services.{services.First().Name}" },
				{ "Available", services.FirstOrDefault(service => service.Available) != null },
				{ "Running", services.FirstOrDefault(service => service.Running) != null }
			})
			.ToJArray();
		#endregion

		#region Process inter-communicate messages
		public async Task SendInterCommunicateMessageAsync(string type, JToken data = null)
		{
			var message = new CommunicateMessage("APIGateway")
			{
				Type = type,
				Data = data ?? new JObject()
			};
			try
			{
				await message.SendAsync().ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				if (ex is WampException)
					try
					{
						await Task.Delay(UtilityService.GetRandomNumber(456, 789)).ConfigureAwait(false);
						await message.SendAsync().ConfigureAwait(false);
					}
					catch (Exception exception)
					{
						Global.OnError?.Invoke($"Error occurred while sending an inter-communicate message => {exception.Message}", exception);
					}
				else
					Global.OnError?.Invoke($"Error occurred while sending an inter-communicate message => {ex.Message}", ex);
			}
		}

		void ProcessInterCommunicateMessage(CommunicateMessage message)
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
#if DEBUG
						Global.OnProcess?.Invoke($"{(message.Type.ToArray('#').Last().IsEquals("info") ? "Got information of a controller" : "A controller was connected")} => {message.ToJson()}");
#endif
						break;

					case "disconnect":
						controller = message.Data.FromJson<ControllerInfo>();
						if (this.Controllers.TryGetValue(controller.ID, out controller))
						{
							controller.Available = false;
							controller.Timestamp = DateTime.Now;
							this.Services.ForEach(kvp =>
							{
								var svcInfo = kvp.Value.FirstOrDefault(svc => svc.Name.IsEquals(kvp.Key) && svc.ControllerID.IsEquals(controller.ID));
								if (svcInfo != null)
									svcInfo.Available = svcInfo.Running = false;
							});
						}
#if DEBUG
						Global.OnProcess?.Invoke($"A controller was disconnected => {message.ToJson()}");
#endif
						break;

					case "requestinfo":
						this.RequestTime = DateTime.Now;
#if DEBUG
						Global.OnProcess?.Invoke($"Got a request to update information of a controller => {message.ToJson()}");
#endif
						break;
				}
			}

			// service info
			else if (message.Type.IsEquals("Service#Info"))
			{
				var serviceInfo = message.Data.FromJson<ServiceInfo>();

				if (!this.Services.TryGetValue(serviceInfo.Name.ToLower(), out var services))
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

		Task SendRequestInfoAsync()
			=> Task.WhenAll(this.SendInterCommunicateMessageAsync("Controller#RequestInfo"), this.SendInterCommunicateMessageAsync("Service#RequestInfo"));
		#endregion

	}
}