#region Related components
using System;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Logging;
using WampSharp.Binding;
using WampSharp.Core.Serialization;
using WampSharp.V2;
using WampSharp.V2.Core;
using WampSharp.V2.Core.Contracts;
using WampSharp.V2.Realm;
using WampSharp.V2.PubSub;
using WampSharp.V2.Rpc;
using WampSharp.V2.Client;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class Router
	{
		public static void Connect(List<Action<object, WampSessionCreatedEventArgs>> onIncomingConnectionEstablished = null, List<Action<object, WampSessionCreatedEventArgs>> onOutgoingConnectionEstablished = null, int waitingTimes = 6789)
		{
			Global.Logger.LogInformation($"Attempting to connect to API Gateway Router [{new Uri(Services.Router.GetRouterStrInfo()).GetResolvedURI()}]");
			Global.Connect(
				(sender, arguments) =>
				{
					onIncomingConnectionEstablished?.ForEach(action =>
					{
						try
						{
							action?.Invoke(sender, arguments);
						}
						catch (Exception ex)
						{
							Global.Logger.LogError($"Error occurred while calling on-incoming action => {ex.Message}", ex);
						}
					});

					Global.PrimaryInterCommunicateMessageUpdater?.Dispose();
					Global.PrimaryInterCommunicateMessageUpdater = Services.Router.IncomingChannel?.RealmProxy.Services
						.GetSubject<CommunicateMessage>("messages.services.apigateway")
						.Subscribe(
							async message =>
							{
								try
								{
									await RESTfulAPIs.ProcessInterCommunicateMessageAsync(message).ConfigureAwait(false);
								}
								catch (Exception ex)
								{
									await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.Updates", $"{ex.Message} => {message?.ToJson().ToString(RESTfulAPIs.JsonFormat)}", ex).ConfigureAwait(false);
								}
							},
							async exception => await Global.WriteLogsAsync(WebSocketAPIs.Logger, "Http.Updates", $"Error occurred while fetching an inter-communicating message => {exception.Message}", exception).ConfigureAwait(false)
						);
				},
				async (sender, arguments) =>
				{
					onOutgoingConnectionEstablished?.ForEach(action =>
					{
						try
						{
							action?.Invoke(sender, arguments);
						}
						catch (Exception ex)
						{
							Global.Logger.LogError($"Error occurred while calling on-outgoing action => {ex.Message}", ex);
						}
					});

					await Task.WhenAll
					(
						Global.RegisterServiceAsync("Http.APIs"),
						Task.Delay(UtilityService.GetRandomNumber(234, 567), Global.CancellationToken)
					).ConfigureAwait(false);

					while (Services.Router.IncomingChannel == null)
						await Task.Delay(UtilityService.GetRandomNumber(234, 567), Global.CancellationToken).ConfigureAwait(false);

					new CommunicateMessage("APIGateway") { Type = "Controller#RequestInfo" }.Send();
					new CommunicateMessage("APIGateway") { Type = "Service#RequestInfo" }.Send();
				},
				waitingTimes,
				exception => Global.Logger.LogError($"Cannot connect to API Gateway Router in period of times => {exception.Message}", exception),
				exception => Global.Logger.LogError($"Error occurred while connecting to API Gateway Router => {exception.Message}", exception)
			);
		}

		public static void Disconnect(int waitingTimes = 1234)
		{
			Global.UnregisterService("Http.APIs", waitingTimes);
			Global.PrimaryInterCommunicateMessageUpdater?.Dispose();
			Global.SecondaryInterCommunicateMessageUpdater?.Dispose();
			Global.Disconnect(waitingTimes);
		}

		static IWampHost Forwarder { get; set; }

		public static ConcurrentDictionary<long, IAsyncDisposable> ForwardingTokens { get; } = new ConcurrentDictionary<long, IAsyncDisposable>();

		public static void OpenForwarder(IApplicationBuilder appBuilder)
		{
			var routerInfo = Services.Router.GetRouterInfo();
			Global.Logger.LogInformation($"Initialize the forwarder of API Gateway Router [{UtilityService.GetAppSetting("HttpUri:APIs")}/router]");
			Router.Forwarder = new WampHost(new ForwardingRealmContainer($"{routerInfo.Item1}{(routerInfo.Item1.EndsWith("/") ? "" : "/")}{routerInfo.Item2}", routerInfo.Item3));

			appBuilder
				.UseForwardedHeaders(Global.GetForwardedHeadersOptions())
				.UseWebSockets(new WebSocketOptions
				{
					KeepAliveInterval = WebSocketAPIs.KeepAliveInterval
				});
			Router.Forwarder.RegisterTransport(new WampSharp.AspNetCore.WebSockets.Server.AspNetCoreWebSocketTransport(appBuilder), new JTokenJsonBinding(), new JTokenMessagePackBinding());
			Global.Logger.LogInformation("The transport of forwarder of API Gateway Router was registered (ASP.NET Core WebSocket)");

			Router.Forwarder.Open();
			Global.Logger.LogInformation($"The forwarder of API Gateway Router is ready for serving [{UtilityService.GetAppSetting("HttpUri:APIs")}/router => {new Uri(Services.Router.GetRouterStrInfo()).GetResolvedURI()}]");
		}

		public static void CloseForwarder()
			=> Task.Run(async () => await Router.ForwardingTokens.Values.ToList().ForEachAsync(async forwardingToken => await forwardingToken.DisposeAsync().ConfigureAwait(false)).ConfigureAwait(false))
				.ContinueWith(_ => Router.Forwarder?.Dispose(), TaskContinuationOptions.OnlyOnRanToCompletion)
				.ContinueWith(_ => Global.Logger.LogInformation("The forwarder of API Gateway Router was disposed"), TaskContinuationOptions.OnlyOnRanToCompletion)
				.Run(true);
	}

	class ForwardingToken : IWampRegistrationSubscriptionToken
	{
		readonly IWampRegistrationSubscriptionToken _localToken;
		IAsyncDisposable _remoteToken;

		public long TokenId => this._localToken.TokenId;

		public ForwardingToken(IWampRegistrationSubscriptionToken localToken, Task<IAsyncDisposable> remoteToken)
		{
			this._localToken = localToken;
			Task.Run(() => this.RegisterForwardingTokenAsync(remoteToken)).ConfigureAwait(false);
		}

		public async Task RegisterForwardingTokenAsync(Task<IAsyncDisposable> remoteToken)
		{
			try
			{
				await this.UnregisterForwardingTokenAsync().ConfigureAwait(false);
				this._remoteToken = await remoteToken.ConfigureAwait(false);
				Router.ForwardingTokens.TryAdd(this.TokenId, this._remoteToken);
			}
			catch (Exception ex)
			{
				Global.Logger.LogError($"Error occurred while registering/subscribing with API Gateway Router => {ex.Message}", ex);
			}
		}

		public async Task UnregisterForwardingTokenAsync()
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
			GC.SuppressFinalize(this);
			Task.Run(() => this.UnregisterForwardingTokenAsync()).ConfigureAwait(false);
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
				await forwardingToken.UnregisterForwardingTokenAsync().ConfigureAwait(false);
				remoteToken = null;
			};
			this._channel.RealmProxy.Monitor.ConnectionError += async (sender, args) =>
			{
				await forwardingToken.UnregisterForwardingTokenAsync().ConfigureAwait(false);
				remoteToken = null;
			};
			this._channel.RealmProxy.Monitor.ConnectionEstablished += async (sender, args) =>
			{
				if (remoteToken == null)
				{
					remoteToken = this._channel.RealmProxy.RpcCatalog.Register(operation, options);
					await forwardingToken.RegisterForwardingTokenAsync(remoteToken).ConfigureAwait(false);
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
			var topic = this._channel.RealmProxy.TopicContainer.GetTopicByUri(topicUri);
			if (args != null && argsKeywords != null)
				Task.Run(() => topic.Publish(options, args, argsKeywords)).ConfigureAwait(false);
			else if (args != null)
				Task.Run(() => topic.Publish(options, args)).ConfigureAwait(false);
			else
				Task.Run(() => topic.Publish(options)).ConfigureAwait(false);
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
				await forwardingToken.UnregisterForwardingTokenAsync().ConfigureAwait(false);
				remoteToken = null;
			};
			this._channel.RealmProxy.Monitor.ConnectionError += async (sender, args) =>
			{
				await forwardingToken.UnregisterForwardingTokenAsync().ConfigureAwait(false);
				remoteToken = null;
			};
			this._channel.RealmProxy.Monitor.ConnectionEstablished += async (sender, args) =>
			{
				if (remoteToken == null)
				{
					remoteToken = this._channel.RealmProxy.TopicContainer.GetTopicByUri(topicUri).Subscribe(new ForwardingTopicSubscriber(subscriber, this._topicContainer), options);
					await forwardingToken.RegisterForwardingTokenAsync(remoteToken).ConfigureAwait(false);
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
				=> this._topicContainer.GetTopicByUri(details.Topic)?.Publish(formatter, publicationId, new PublishOptions { Acknowledge = true });

			public void Event<TMessage>(IWampFormatter<TMessage> formatter, long publicationId, EventDetails details, TMessage[] arguments)
				=> this._topicContainer.GetTopicByUri(details.Topic)?.Publish(formatter, publicationId, new PublishOptions { Acknowledge = true }, arguments);

			public void Event<TMessage>(IWampFormatter<TMessage> formatter, long publicationId, EventDetails details, TMessage[] arguments, IDictionary<string, TMessage> argumentsKeywords)
				=> this._topicContainer.GetTopicByUri(details.Topic)?.Publish(formatter, publicationId, new PublishOptions { Acknowledge = true }, arguments, argumentsKeywords);

			public void Event<TMessage>(IWampFormatter<TMessage> formatter, long publicationId, PublishOptions options)
				=> this._subscriber.Event(formatter, publicationId, options);

			public void Event<TMessage>(IWampFormatter<TMessage> formatter, long publicationId, PublishOptions options, TMessage[] arguments)
				=> this._subscriber.Event(formatter, publicationId, options, arguments);

			public void Event<TMessage>(IWampFormatter<TMessage> formatter, long publicationId, PublishOptions options, TMessage[] arguments, IDictionary<string, TMessage> argumentsKeywords)
				=> this._subscriber.Event(formatter, publicationId, options, arguments, argumentsKeywords);
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
	}

}