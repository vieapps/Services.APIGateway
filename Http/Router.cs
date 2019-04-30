﻿#region Related components
using System;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Logging;
using WampSharp.Binding;
using WampSharp.Core.Serialization;
using WampSharp.AspNetCore.WebSockets.Server;
using WampSharp.V2;
using WampSharp.V2.Core;
using WampSharp.V2.Core.Contracts;
using WampSharp.V2.Authentication;
using WampSharp.V2.Realm;
using WampSharp.V2.PubSub;
using WampSharp.V2.Rpc;
using WampSharp.V2.Client;
using WampSharp.V2.Transports;
using WampSharp.V2.Binding;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class Router
	{
		public static void Connect(int waitingTimes = 6789)
		{
			Global.Logger.LogDebug($"Attempting to connect to API Gateway Router [{new Uri(Services.Router.GetRouterStrInfo()).GetResolvedURI()}]");
			Global.OpenRouterChannels(
				(sender, arguments) =>
				{
					Global.Logger.LogDebug($"Incoming channel to API Gateway Router is established - Session ID: {arguments.SessionId}");
					Services.Router.IncomingChannel.Update(Services.Router.IncomingChannelSessionID, Global.ServiceName, $"Incoming ({Global.ServiceName} HTTP service)");
					Global.PrimaryInterCommunicateMessageUpdater?.Dispose();
					Global.PrimaryInterCommunicateMessageUpdater = Services.Router.IncomingChannel.RealmProxy.Services
						.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages.apigateway")
						.Subscribe(
							async message =>
							{
								try
								{
									await InternalAPIs.ProcessInterCommunicateMessageAsync(message).ConfigureAwait(false);
								}
								catch (Exception ex)
								{
									await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs", $"{ex.Message} => {message?.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}", ex).ConfigureAwait(false);
								}
							},
							async exception => await Global.WriteLogsAsync(RTU.Logger, "Http.InternalAPIs", $"Error occurred while fetching an inter-communicating message => {exception.Message}", exception).ConfigureAwait(false)
						);
				},
				(sender, arguments) =>
				{
					Global.Logger.LogDebug($"Outgoing channel to API Gateway Router is established - Session ID: {arguments.SessionId}");
					Services.Router.OutgoingChannel.Update(Services.Router.OutgoingChannelSessionID, Global.ServiceName, $"Outgoing ({Global.ServiceName} HTTP service)");
					Task.Run(async () =>
					{
						try
						{
							await Task.WhenAll(
								Global.InitializeLoggingServiceAsync(),
								Global.InitializeRTUServiceAsync()
							).ConfigureAwait(false);
							Global.Logger.LogInformation("Helper services are succesfully initialized");
							while (Services.Router.IncomingChannel == null || Services.Router.OutgoingChannel == null)
								await Task.Delay(UtilityService.GetRandomNumber(234, 567), Global.CancellationTokenSource.Token).ConfigureAwait(false);
						}
						catch (Exception ex)
						{
							Global.Logger.LogError($"Error occurred while initializing helper services: {ex.Message}", ex);
						}
					})
					.ContinueWith(async _ => await Global.RegisterServiceAsync("Http.InternalAPIs").ConfigureAwait(false), TaskContinuationOptions.OnlyOnRanToCompletion)
					.ContinueWith(async _ => await Global.PublishAsync(new CommunicateMessage
					{
						ServiceName = "APIGateway",
						Type = "Controller#RequestInfo"
					}, Global.Logger, "Http.InternalAPIs").ConfigureAwait(false), TaskContinuationOptions.OnlyOnRanToCompletion)
					.ContinueWith(async _ => await Global.PublishAsync(new CommunicateMessage
					{
						ServiceName = "APIGateway",
						Type = "Service#RequestInfo"
					}, Global.Logger, "Http.InternalAPIs").ConfigureAwait(false), TaskContinuationOptions.OnlyOnRanToCompletion)
					.ConfigureAwait(false);
				},
				waitingTimes
			);
		}

		public static void Disconnect(int waitingTimes = 1234)
		{
			Global.UnregisterService("Http.InternalAPIs", waitingTimes);
			Global.PrimaryInterCommunicateMessageUpdater?.Dispose();
			Global.SecondaryInterCommunicateMessageUpdater?.Dispose();
			Services.Router.CloseChannels();
		}

		static WampHost Forwarder { get; set; }

		public static ConcurrentDictionary<long, SystemEx.IAsyncDisposable> ForwardingTokens { get; } = new ConcurrentDictionary<long, SystemEx.IAsyncDisposable>();

		public static void InitializeForwarder()
		{
			Global.Logger.LogInformation("Initialize the forwarder of API Gateway Router");
			var routerInfo = Services.Router.GetRouterInfo();
			Router.Forwarder = new WampHost(new ForwardingRealmContainer($"{routerInfo.Item1}{(routerInfo.Item1.EndsWith("/") ? "" : "/")}{routerInfo.Item2}", routerInfo.Item3));
		}

		public static void RegisterForwarderTransport(IApplicationBuilder appBuilder)
		{
			appBuilder.UseWebSockets();
			var transport = new AspNetCoreWebSocketTransport(appBuilder);
			Router.Forwarder.RegisterTransport(transport, new JTokenJsonBinding(), new JTokenMsgpackBinding());
			Global.Logger.LogInformation($"The transport of forwarder of API Gateway Router is registered => {transport.GetType()}");
		}

		public static void OpenForwarder()
		{
			Router.Forwarder.Open();
			Global.Logger.LogInformation("The forwarder of API Gateway Router is ready for serving");
		}

		public static void CloseForwarder()
			=> Task.Run(async () => await Router.ForwardingTokens.Values.ForEachAsync((forwardingToken, cancellationToken) => forwardingToken.DisposeAsync()).ConfigureAwait(false))
				.ContinueWith(_ => Router.Forwarder?.Dispose(), TaskContinuationOptions.OnlyOnRanToCompletion)
				.ContinueWith(_ => Global.Logger.LogInformation("The forwarder of API Gateway Router is stopped"), TaskContinuationOptions.OnlyOnRanToCompletion)
				.ConfigureAwait(false)
				.GetAwaiter()
				.GetResult();
	}

	class ForwardingToken : IWampRegistrationSubscriptionToken
	{
		readonly IWampRegistrationSubscriptionToken _localToken;
		SystemEx.IAsyncDisposable _remoteToken;

		public long TokenId => this._localToken.TokenId;

		public ForwardingToken(IWampRegistrationSubscriptionToken localToken, Task<SystemEx.IAsyncDisposable> remoteToken)
		{
			this._localToken = localToken;
			Task.Run(() => this.ForwardingRegisterAsync(remoteToken)).ConfigureAwait(false);
		}

		public async Task ForwardingRegisterAsync(Task<SystemEx.IAsyncDisposable> remoteToken)
		{
			try
			{
				await this.ForwardingUnregisterAsync().ConfigureAwait(false);
				this._remoteToken = await remoteToken.ConfigureAwait(false);
				Router.ForwardingTokens.TryAdd(this.TokenId, this._remoteToken);
			}
			catch (Exception ex)
			{
				Global.Logger.LogError($"Error occurred while registering with API Gateway Router => {ex.Message}", ex);
			}
		}

		public async Task ForwardingUnregisterAsync()
		{
			if (this._remoteToken != null)
				try
				{
					Router.ForwardingTokens.Remove(this.TokenId, out var token);
					await this._remoteToken.DisposeAsync().ConfigureAwait(false);
					this._remoteToken = null;
				}
				catch { }
		}

		public void Dispose()
		{
			Task.Run(() => this.ForwardingUnregisterAsync()).ConfigureAwait(false);
			this._localToken.Dispose();
		}

		~ForwardingToken()
			=> this.Dispose();
	}

	class ForwardingRpcCatalog : IWampRpcOperationCatalog
	{
		public ForwardingRpcCatalog(IWampRpcOperationCatalog rpcCatalog, IWampChannel channel)
		{
			this._rpcCatalog = rpcCatalog;
			this._channel = channel;
		}

		readonly IWampRpcOperationCatalog _rpcCatalog;
		readonly IWampChannel _channel;

		public event EventHandler<WampProcedureRegisterEventArgs> RegistrationAdded
		{
			add => this._rpcCatalog.RegistrationAdded += value;
			remove => this._rpcCatalog.RegistrationAdded -= value;
		}

		public event EventHandler<WampProcedureRegisterEventArgs> RegistrationRemoved
		{
			add => this._rpcCatalog.RegistrationRemoved += value;
			remove => this._rpcCatalog.RegistrationRemoved -= value;
		}

		public IWampRpcOperation GetMatchingOperation(string criteria)
			=> this._rpcCatalog.GetMatchingOperation(criteria);

		IWampCancellableInvocation Invoke<TMessage>(IWampRawRpcOperationRouterCallback caller, string procedure, TMessage[] arguments = null, IDictionary<string, TMessage> argumentsKeywords = null)
		{
			var callback = new ForwardingRpcOperationCallback(caller);
			var args = arguments?.Select(arg => (object)arg).ToArray();
			var argsKeywords = argumentsKeywords?.ToDictionary(kvp => kvp.Key, kvp => (object)kvp.Value);
			var options = new CallOptions
			{
				//DiscloseMe = true
			};
			var invocationProxy = args != null && argsKeywords != null
				? this._channel.RealmProxy.RpcCatalog.Invoke(callback, options, procedure, args, argsKeywords)
				: args != null
					? this._channel.RealmProxy.RpcCatalog.Invoke(callback, options, procedure, args)
					: this._channel.RealmProxy.RpcCatalog.Invoke(callback, options, procedure);
			return new ForwardingCancellableInvocation(invocationProxy);
		}

		public IWampCancellableInvocation Invoke<TMessage>(IWampRawRpcOperationRouterCallback caller, IWampFormatter<TMessage> formatter, InvocationDetails details, string procedure)
			=> this.Invoke<TMessage>(caller, procedure);

		public IWampCancellableInvocation Invoke<TMessage>(IWampRawRpcOperationRouterCallback caller, IWampFormatter<TMessage> formatter, InvocationDetails details, string procedure, TMessage[] arguments)
			=> this.Invoke(caller, procedure, arguments);

		public IWampCancellableInvocation Invoke<TMessage>(IWampRawRpcOperationRouterCallback caller, IWampFormatter<TMessage> formatter, InvocationDetails details, string procedure, TMessage[] arguments, IDictionary<string, TMessage> argumentsKeywords)
			=> this.Invoke(caller, procedure, arguments, argumentsKeywords);

		public IWampRegistrationSubscriptionToken Register(IWampRpcOperation operation, RegisterOptions options)
		{
			var localToken = this._rpcCatalog.Register(operation, options);
			var remoteToken = this._channel.RealmProxy.RpcCatalog.Register(operation, options);
			var forwardingToken = new ForwardingToken(localToken, remoteToken);

			this._channel.RealmProxy.Monitor.ConnectionBroken += async (sender, args) =>
			{
				await forwardingToken.ForwardingUnregisterAsync().ConfigureAwait(false);
				remoteToken = null;
			};
			this._channel.RealmProxy.Monitor.ConnectionError += async (sender, args) =>
			{
				await forwardingToken.ForwardingUnregisterAsync().ConfigureAwait(false);
				remoteToken = null;
			};
			this._channel.RealmProxy.Monitor.ConnectionEstablished += async (sender, args) =>
			{
				if (remoteToken == null)
				{
					remoteToken = this._channel.RealmProxy.RpcCatalog.Register(operation, options);
					await forwardingToken.ForwardingRegisterAsync(remoteToken).ConfigureAwait(false);
				}
			};

			return forwardingToken;
		}

		class ForwardingRpcOperationCallback : IWampRawRpcOperationClientCallback
		{
			readonly IWampRawRpcOperationRouterCallback _caller;

			public ForwardingRpcOperationCallback(IWampRawRpcOperationRouterCallback caller)
				=> this._caller = caller;

			public void Result<TMessage>(IWampFormatter<TMessage> formatter, ResultDetails details)
				=> this._caller.Result(formatter, new YieldOptions());

			public void Result<TMessage>(IWampFormatter<TMessage> formatter, ResultDetails details, TMessage[] arguments)
				=> this._caller.Result(formatter, new YieldOptions(), arguments);

			public void Result<TMessage>(IWampFormatter<TMessage> formatter, ResultDetails details, TMessage[] arguments, IDictionary<string, TMessage> argumentsKeywords)
				=> this._caller.Result(formatter, new YieldOptions(), arguments, argumentsKeywords);

			public void Error<TMessage>(IWampFormatter<TMessage> formatter, TMessage details, string error)
				=> this._caller.Error(formatter, details, error);

			public void Error<TMessage>(IWampFormatter<TMessage> formatter, TMessage details, string error, TMessage[] arguments)
				=> this._caller.Error(formatter, details, error, arguments);

			public void Error<TMessage>(IWampFormatter<TMessage> formatter, TMessage details, string error, TMessage[] arguments, TMessage argumentsKeywords)
				=> this._caller.Error(formatter, details, error, arguments, argumentsKeywords);
		}

		class ForwardingCancellableInvocation : IWampCancellableInvocation
		{
			readonly IWampCancellableInvocationProxy _invocationProxy;

			public ForwardingCancellableInvocation(IWampCancellableInvocationProxy invocationProxy)
				=> this._invocationProxy = invocationProxy;

			public void Cancel(InterruptDetails details)
				=> this._invocationProxy.Cancel(new CancelOptions
				{
					Mode = details.Mode,
					OriginalValue = details.OriginalValue
				});
		}
	}

	class ForwardingTopicContainer : IWampTopicContainer
	{
		readonly IWampTopicContainer _topicContainer;
		readonly IWampChannel _channel;

		public ForwardingTopicContainer(IWampTopicContainer topicContainer, IWampChannel channel)
		{
			this._topicContainer = topicContainer;
			this._channel = channel;
		}

		public IEnumerable<string> TopicUris => this._topicContainer.TopicUris;

		public IEnumerable<IWampTopic> Topics => this._topicContainer.Topics;

		public event EventHandler<WampTopicCreatedEventArgs> TopicCreated
		{
			add => this._topicContainer.TopicCreated += value;
			remove => this._topicContainer.TopicCreated -= value;
		}

		public event EventHandler<WampTopicRemovedEventArgs> TopicRemoved
		{
			add => this._topicContainer.TopicRemoved += value;
			remove => this._topicContainer.TopicRemoved -= value;
		}

		public IWampTopic CreateTopicByUri(string topicUri, bool persistent)
			=> this._topicContainer.CreateTopicByUri(topicUri, persistent);

		public IWampTopic GetOrCreateTopicByUri(string topicUri)
			=> this._topicContainer.GetOrCreateTopicByUri(topicUri);

		public IWampTopic GetTopicByUri(string topicUri)
			=> this._topicContainer.GetTopicByUri(topicUri);

		public bool TryRemoveTopicByUri(string topicUri, out IWampTopic topic)
			=> this._topicContainer.TryRemoveTopicByUri(topicUri, out topic);

		public IWampCustomizedSubscriptionId GetSubscriptionId(string topicUri, SubscribeOptions options)
			=> this._topicContainer.GetSubscriptionId(topicUri, options);

		public IEnumerable<IWampTopic> GetMatchingTopics(string criteria)
			=> this._topicContainer.GetMatchingTopics(criteria);

		void Publish<TMessage>(string topicUri, PublishOptions options, TMessage[] arguments = null, IDictionary<string, TMessage> argumentsKeywords = null)
		{
			var args = arguments?.Select(arg => (object)arg).ToArray();
			var argsKeywords = argumentsKeywords?.ToDictionary(kvp => kvp.Key, kvp => (object)kvp.Value);
			var topicProxy = this._channel.RealmProxy.TopicContainer.GetTopicByUri(topicUri);
			if (args != null && argsKeywords != null)
				Task.Run(() => topicProxy.Publish(options, args, argsKeywords)).ConfigureAwait(false);
			else if (args != null)
				Task.Run(() => topicProxy.Publish(options, args)).ConfigureAwait(false);
			else
				Task.Run(() => topicProxy.Publish(options)).ConfigureAwait(false);
		}

		public long Publish<TMessage>(IWampFormatter<TMessage> formatter, PublishOptions options, string topicUri)
		{
			this.Publish<TMessage>(topicUri, options);
			return this._topicContainer.Publish(formatter, options, topicUri);
		}

		public long Publish<TMessage>(IWampFormatter<TMessage> formatter, PublishOptions options, string topicUri, TMessage[] arguments)
		{
			this.Publish(topicUri, options, arguments);
			return this._topicContainer.Publish(formatter, options, topicUri, arguments);
		}

		public long Publish<TMessage>(IWampFormatter<TMessage> formatter, PublishOptions options, string topicUri, TMessage[] arguments, IDictionary<string, TMessage> argumentKeywords)
		{
			this.Publish(topicUri, options, arguments, argumentKeywords);
			return this._topicContainer.Publish(formatter, options, topicUri, arguments, argumentKeywords);
		}

		public IWampRegistrationSubscriptionToken Subscribe(IWampRawTopicRouterSubscriber subscriber, string topicUri, SubscribeOptions options)
		{
			var localToken = this._topicContainer.Subscribe(subscriber, topicUri, options);
			var remoteToken = this._channel.RealmProxy.TopicContainer.GetTopicByUri(topicUri).Subscribe(new ForwardingTopicSubscriber(subscriber, this._topicContainer), options);
			var forwardingToken = new ForwardingToken(localToken, remoteToken);

			this._channel.RealmProxy.Monitor.ConnectionBroken += async (sender, args) =>
			{
				await forwardingToken.ForwardingUnregisterAsync().ConfigureAwait(false);
				remoteToken = null;
			};
			this._channel.RealmProxy.Monitor.ConnectionError += async (sender, args) =>
			{
				await forwardingToken.ForwardingUnregisterAsync().ConfigureAwait(false);
				remoteToken = null;
			};
			this._channel.RealmProxy.Monitor.ConnectionEstablished += async (sender, args) =>
			{
				if (remoteToken == null)
				{
					remoteToken = this._channel.RealmProxy.TopicContainer.GetTopicByUri(topicUri).Subscribe(new ForwardingTopicSubscriber(subscriber, this._topicContainer), options);
					await forwardingToken.ForwardingRegisterAsync(remoteToken).ConfigureAwait(false);
				}
			};

			return forwardingToken;
		}

		class ForwardingTopicSubscriber : IWampRawTopicClientSubscriber, IWampRawTopicRouterSubscriber
		{
			private readonly IWampTopicContainer _topicContainer;
			private readonly IWampRawTopicRouterSubscriber _subscriber;

			public ForwardingTopicSubscriber(IWampRawTopicRouterSubscriber subscriber, IWampTopicContainer topicContainer)
			{
				this._subscriber = subscriber;
				this._topicContainer = topicContainer;
			}

			public void Event<TMessage>(IWampFormatter<TMessage> formatter, long publicationId, EventDetails details)
			{
				var topic = this._topicContainer.GetTopicByUri(details.Topic);
				if (topic != null)
					topic.Publish(formatter, publicationId, new PublishOptions()
					{
						//DiscloseMe = true,
						Acknowledge = true
					});
			}

			public void Event<TMessage>(IWampFormatter<TMessage> formatter, long publicationId, EventDetails details, TMessage[] arguments)
			{
				var topic = this._topicContainer.GetTopicByUri(details.Topic);
				if (topic != null)
					topic.Publish(formatter, publicationId, new PublishOptions()
					{
						//DiscloseMe = true,
						Acknowledge = true
					}, arguments);
			}

			public void Event<TMessage>(IWampFormatter<TMessage> formatter, long publicationId, EventDetails details, TMessage[] arguments, IDictionary<string, TMessage> argumentsKeywords)
			{
				var topic = this._topicContainer.GetTopicByUri(details.Topic);
				if (topic != null)
					topic.Publish(formatter, publicationId, new PublishOptions()
					{
						//DiscloseMe = true,
						Acknowledge = true
					}, arguments, argumentsKeywords);
			}

			public void Event<TMessage>(IWampFormatter<TMessage> formatter, long publicationId, PublishOptions options)
				=> this._subscriber.Event(formatter, publicationId, options);

			public void Event<TMessage>(IWampFormatter<TMessage> formatter, long publicationId, PublishOptions options, TMessage[] arguments)
				=> this._subscriber.Event(formatter, publicationId, options, arguments);

			public void Event<TMessage>(IWampFormatter<TMessage> formatter, long publicationId, PublishOptions options, TMessage[] arguments, IDictionary<string, TMessage> argumentsKeywords)
				=> this._subscriber.Event(formatter, publicationId, options, arguments, argumentsKeywords);
		}
	}

	class ForwardingRealm : IWampRealm
	{
		public string Name { get; private set; }

		public IWampRpcOperationCatalog RpcCatalog { get; private set; }

		public IWampTopicContainer TopicContainer { get; private set; }

		public ForwardingRealm(IWampChannel channel, IWampRealm realm)
		{
			try
			{
				channel.RealmProxy.Monitor.ConnectionBroken += (sender, args) =>
				{
					if (!Services.Router.ChannelsAreClosedBySystem)
						channel.ReOpen();
				};
				channel.Open().Wait(1234);
				this.Name = realm.Name;
				this.RpcCatalog = new ForwardingRpcCatalog(realm.RpcCatalog, channel);
				this.TopicContainer = new ForwardingTopicContainer(realm.TopicContainer, channel);
			}
			catch (Exception ex)
			{
				Global.Logger.LogError($"Error occurred while initializing a realm of forwarder of API Gateway Router => {ex.Message}", ex);
			}
		}
	}

	class ForwardingRealmContainer : IWampRealmContainer
	{
		readonly string _routerURI;
		readonly bool _useJsonChannel;
		readonly IWampClientAuthenticator _authenticator;

		public ForwardingRealmContainer(string routerURI, bool useJsonChannel, IWampClientAuthenticator authenticator = null)
		{
			this._routerURI = routerURI;
			this._useJsonChannel = useJsonChannel;
			this._authenticator = authenticator;
		}

		public IWampRealm GetRealmByName(string name)
		{
			var channel = this._useJsonChannel
				? new DefaultWampChannelFactory().CreateJsonChannel(this._routerURI, name, this._authenticator)
				: new DefaultWampChannelFactory().CreateMsgpackChannel(this._routerURI, name, this._authenticator);
			return new ForwardingRealm(channel, new WampRealmContainer().GetRealmByName(name));
		}
	}

}