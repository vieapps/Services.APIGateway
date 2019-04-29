#region Related components
using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class LoggingService : ILoggingService, IDisposable
	{

		#region Properties
		static string _LogsPath = null;

		internal static string LogsPath => LoggingService._LogsPath ?? (LoggingService._LogsPath = Global.GetPath("Path:Logs", "logs"));

		ConcurrentDictionary<string, ConcurrentQueue<string>> Logs { get; } = new ConcurrentDictionary<string, ConcurrentQueue<string>>();

		CancellationTokenSource CancellationTokenSource { get; }

		int MaxItems { get; set; } = 13;

		SemaphoreSlim Locker { get; } = new SemaphoreSlim(1, 1);
		#endregion

		public LoggingService(CancellationToken cancellationToken = default(CancellationToken))
		{
			this.CancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

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
		}

		public void Dispose() => this.CancellationTokenSource.Cancel();

		~LoggingService()
		{
			this.Dispose();
			this.CancellationTokenSource.Dispose();
		}

		void WriteLogs(string correlationID, string serviceName, string objectName, List<string> logMessages, string stack = null)
		{
			// prepare
			var time = DateTime.Now.ToString("HH:mm:ss.fff");
			var name = (!string.IsNullOrWhiteSpace(serviceName) ? serviceName : "APIGateway").ToLower();
			var surfix = !string.IsNullOrWhiteSpace(objectName) && !objectName.IsEquals(serviceName) ? "." + objectName.ToLower() : "";

			if (!this.Logs.TryGetValue(name + surfix, out ConcurrentQueue<string> logItems))
			{
				logItems = new ConcurrentQueue<string>();
				this.Logs.TryAdd(name + surfix, logItems);
			}

			// normal logs
			var messages = "";
			logMessages?.Where(log => !string.IsNullOrWhiteSpace(log)).ForEach(log =>
			{
				logItems.Enqueue($"{time}\t{correlationID}\t{log}");
				messages += (!messages.Equals("") ? "\r\n" : "") + $"{time}\t{correlationID}\t{log}";
			});

			if (!string.IsNullOrWhiteSpace(stack))
			{
				logItems.Enqueue($"==> Stack:\r\n{stack}");
				messages += (!messages.Equals("") ? "\r\n" : "") + $"==> Stack:\r\n{stack}";
			}

			// write files
			if (logItems.Count >= this.MaxItems)
				Task.Run(() => this.FlushLogsAsync(name + surfix, logItems)).ConfigureAwait(false);

			// update to controller
			Global.OnLogsUpdated(serviceName, messages);
		}

		public Task WriteLogsAsync(string correlationID, string serviceName, string objectName, List<string> logs, string stack = null, CancellationToken cancellationToken = default(CancellationToken))
			=> UtilityService.ExecuteTask(() => this.WriteLogs(correlationID, serviceName, objectName, logs, stack), cancellationToken);

		public Task WriteLogAsync(string correlationID, string serviceName, string objectName, string log, string stack = null, CancellationToken cancellationToken = default(CancellationToken))
			=> this.WriteLogsAsync(correlationID, serviceName, objectName, new List<string> { log }, stack, cancellationToken);

		async Task FlushLogsAsync(string name, ConcurrentQueue<string> logs)
		{
			await this.Locker.WaitAsync(this.CancellationTokenSource.Token).ConfigureAwait(false);

			var lines = new List<string>();
			while (logs.TryDequeue(out string log))
				lines.Add(log);

			if (lines.Count > 0)
				try
				{
					var filename = $"{DateTime.Now.ToString("yyyyMMddHH")}_{name}.txt";
					await UtilityService.WriteTextFileAsync(Path.Combine(LoggingService.LogsPath, filename), lines, true, null, this.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch { }

			this.Locker.Release();
		}

		internal void FlushAllLogs()
			=> Task.Run(() => this.Logs.ForEachAsync((kvp, cancellationToken) => this.FlushLogsAsync(kvp.Key, kvp.Value), CancellationToken.None, true, false)).ConfigureAwait(false);
	}
}