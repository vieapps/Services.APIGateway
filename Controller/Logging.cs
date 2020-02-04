#region Related components
using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

using Newtonsoft.Json;
using MongoDB.Bson.Serialization.Attributes;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class LoggingService : ILoggingService, IDisposable
	{

		#region Properties
		static string _LogsPath = null;

		internal static string LogsPath => LoggingService._LogsPath ?? (LoggingService._LogsPath = Global.GetPath("Path:Logs", "logs"));

		ConcurrentDictionary<string, ConcurrentQueue<string>> Logs { get; } = new ConcurrentDictionary<string, ConcurrentQueue<string>>();

		ConcurrentQueue<LoggingItem> LoggingItems { get; } = new ConcurrentQueue<LoggingItem>();

		DataSource LoggingDataSource { get; }

		CancellationTokenSource CancellationTokenSource { get; }

		int MaxItems { get; set; } = 13;

		SemaphoreSlim Locker { get; } = new SemaphoreSlim(1, 1);
		#endregion

		public LoggingService(CancellationToken cancellationToken = default)
		{
#if DEBUG
			this.MaxItems = 3;
#else
			try
			{
				this.MaxItems = UtilityService.GetAppSetting("Logs:MaxItems", "13").CastAs<int>();
			}
			catch
			{
				this.MaxItems = 13;
			}
#endif
			this.LoggingDataSource = RepositoryMediator.GetDataSource(UtilityService.GetAppSetting("Logs:DataSource"));
			this.CancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		}

		public void Dispose()
			=> this.CancellationTokenSource.Cancel();

		~LoggingService()
		{
			this.Dispose();
			this.CancellationTokenSource.Dispose();
		}

		public async Task WriteLogsAsync(string correlationID, string developerID, string appID, string serviceName, string objectName, List<string> logs, string stack = null, CancellationToken cancellationToken = default)
		{
			// prepare
			var loggingItem = new LoggingItem
			{
				CorrelationID = correlationID,
				ServiceName = (string.IsNullOrWhiteSpace(serviceName) ? "APIGateway" : serviceName).ToLower(),
				ObjectName = (string.IsNullOrWhiteSpace(objectName) || objectName.IsEquals(serviceName) ? "" : objectName).ToLower(),
				Logs = "",
				Stack = string.IsNullOrWhiteSpace(stack) ? null : stack
			};

			var time = loggingItem.Time.ToString("HH:mm:ss.fff");
			var name = loggingItem.ServiceName;
			var suffix = $"{(string.IsNullOrWhiteSpace(loggingItem.ObjectName) ? "" : ".")}{loggingItem.ObjectName}";

			if (!this.Logs.TryGetValue(name + suffix, out var logItems))
			{
				logItems = new ConcurrentQueue<string>();
				this.Logs.TryAdd(name + suffix, logItems);
			}

			// normalize & update into queue
			var messages = "";
			logs?.Where(log => !string.IsNullOrWhiteSpace(log)).ForEach(log =>
			{
				logItems.Enqueue($"{time}\t{correlationID}\t{log}");
				messages += (!messages.Equals("") ? "\r\n" : "") + $"{time}\t{correlationID}\t{log}";
				loggingItem.Logs += (!loggingItem.Logs.Equals("") ? "\r\n" : "") + log;
			});

			if (!string.IsNullOrWhiteSpace(stack))
			{
				logItems.Enqueue($"==> Stack:\r\n{stack}");
				messages += (!messages.Equals("") ? "\r\n" : "") + $"==> Stack:\r\n{stack}";
			}

			// update into DB queue
			if (this.LoggingDataSource != null)
				this.LoggingItems.Enqueue(loggingItem);

			// update to controller
			Global.OnLogsUpdated(serviceName, messages);

			// broadcast
			if (Router.OutgoingChannel != null)
				Router.OutgoingChannel.RealmProxy.Services.GetSubject<BaseMessage>("messages.log")?.OnNext(new BaseMessage
				{
					Type = "Update",
					Data = loggingItem.ToJson()
				});

			// flush when reach the max of items
			if (logItems.Count >= this.MaxItems)
			{
				await this.Locker.WaitAsync(this.CancellationTokenSource.Token).ConfigureAwait(false);
				try
				{
					await Task.WhenAll(
						this.FlushIntoFileAsync(name + suffix, logItems, this.CancellationTokenSource.Token),
						this.LoggingDataSource != null ? this.FlushIntoDatabaseAsync(this.CancellationTokenSource.Token) : Task.CompletedTask
					).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke("Error occurred while flushing logs", ex);
				}
				finally
				{
					this.Locker.Release();
				}
			}
		}

		public Task WriteLogAsync(string correlationID, string developerID, string appID, string serviceName, string objectName, string log, string stack = null, CancellationToken cancellationToken = default)
			=> this.WriteLogsAsync(correlationID, developerID, appID, serviceName, objectName, string.IsNullOrWhiteSpace(log) ? null : new List<string> { log }, stack, cancellationToken);

		async Task FlushIntoFileAsync(string name, ConcurrentQueue<string> logs, CancellationToken cancellationToken = default)
		{
			var lines = new List<string>();
			while (logs.TryDequeue(out var log))
				lines.Add(log);

			if (lines.Count > 0)
				try
				{
					var filename = $"{DateTime.Now.ToString("yyyyMMddHH")}_{name}.txt";
					await UtilityService.WriteTextFileAsync(Path.Combine(LoggingService.LogsPath, filename), lines, true, null, cancellationToken).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke("Error occurred while writting log files", ex);
				}
		}

		async Task FlushIntoDatabaseAsync(CancellationToken cancellationToken = default)
		{
			using (var context = new RepositoryContext(true, await this.LoggingDataSource.StartSessionAsync<LoggingItem>(cancellationToken).ConfigureAwait(false)))
			{
				while (this.LoggingItems.TryDequeue(out var logItem))
					await RepositoryMediator.CreateAsync(context, this.LoggingDataSource, logItem, cancellationToken).ConfigureAwait(false);
			}
		}

		internal async Task FlushAsync(CancellationToken cancellationToken = default)
		{
			await this.Locker.WaitAsync(cancellationToken).ConfigureAwait(false);
			try
			{
				await Task.WhenAll(
					this.Logs.ForEachAsync((kvp, token) => this.FlushIntoFileAsync(kvp.Key, kvp.Value, token), cancellationToken, true, false),
					this.LoggingDataSource != null ? this.FlushIntoDatabaseAsync(cancellationToken) : Task.CompletedTask
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke("Error occurred while flushing logs", ex);
			}
			finally
			{
				this.Locker.Release();
			}
		}
	}

	#region Item for storing in database
	[Serializable, BsonIgnoreExtraElements]
	[Entity(CollectionName = "Logs", TableName = "T_Logs")]
	public class LoggingItem : Repository<LoggingItem>
	{
		public LoggingItem() : base()
			=> this.ID = UtilityService.NewUUID;

		[Sortable(IndexName = "Time")]
		public DateTime Time { get; set; } = DateTime.Now;

		[Property(MaxLength = 32, NotNull = true), Sortable(IndexName = "IDs")]
		public string CorrelationID { get; set; }

		[Property(MaxLength = 32), Sortable(IndexName = "IDs")]
		public string DeveloperID { get; set; }

		[Property(MaxLength = 32), Sortable(IndexName = "IDs")]
		public string AppID { get; set; }

		[Property(MaxLength = 50, NotNull = true), Sortable(IndexName = "Services")]
		public new string ServiceName { get; set; }

		[Property(MaxLength = 50, NotNull = true), Sortable(IndexName = "Services")]
		public new string ObjectName { get; set; }

		[Property(NotNull = true, IsCLOB = true)]
		public string Logs { get; set; }

		[Property(IsCLOB = true)]
		public string Stack { get; set; }

		[JsonIgnore, BsonIgnore, Ignore]
		public override string Title { get; set; }

		[JsonIgnore, BsonIgnore, Ignore]
		public override string SystemID { get; set; }

		[JsonIgnore, BsonIgnore, Ignore]
		public override string RepositoryID { get; set; }

		[JsonIgnore, BsonIgnore, Ignore]
		public override string EntityID { get; set; }

		[JsonIgnore, BsonIgnore, Ignore]
		public override Privileges OriginalPrivileges { get; set; }
	}
	#endregion

}