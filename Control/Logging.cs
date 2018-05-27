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
	public class LoggingService : ILoggingService
	{

		#region Properties
		static string _LogsPath = null;
		internal static string LogsPath => LoggingService._LogsPath ?? (LoggingService._LogsPath = Global.GetPath("Path:Logs", "logs"));
		ConcurrentDictionary<string, ConcurrentQueue<string>> Logs { get; } = new ConcurrentDictionary<string, ConcurrentQueue<string>>();
		CancellationTokenSource CancellationTokenSource { get; }
		int MaxItems { get; set; } = 13;
		bool IsFlushing { get; set; } = false;
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

		~LoggingService()
		{
			this.CancellationTokenSource.Cancel();
			this.CancellationTokenSource.Dispose();
		}

		void WriteLogs(string correlationID, string serviceName, string objectName, List<string> logs, string stack = null)
		{
			// prepare
			var time = DateTime.Now.ToString("HH:mm:ss.fff");
			var name = (!string.IsNullOrWhiteSpace(serviceName) ? serviceName : "APIGateway").ToLower();
			var sufix = !string.IsNullOrWhiteSpace(objectName) && !objectName.IsEquals(serviceName) ? "." + objectName.ToLower() : "";

			if (!this.Logs.TryGetValue(name + sufix, out ConcurrentQueue<string> serviceLogs))
			{
				serviceLogs = new ConcurrentQueue<string>();
				this.Logs.TryAdd(name + sufix, serviceLogs);
			}

			if (!this.Logs.TryGetValue(name, out ConcurrentQueue<string> debugLogs))
			{
				debugLogs = new ConcurrentQueue<string>();
				this.Logs.TryAdd(name, debugLogs);
			}

			// normal logs
			var messages = "";
			var errorLogs = new ConcurrentQueue<string>();
			logs?.Where(log => !string.IsNullOrWhiteSpace(log)).ForEach(log =>
			{
				serviceLogs.Enqueue($"{time}\t{correlationID}\t{log}");
				debugLogs.Enqueue($"{time}\t{correlationID}\t{log}");
				if (!string.IsNullOrWhiteSpace(stack))
					errorLogs.Enqueue($"{time}\t{correlationID}\t{log}");
				messages += (!messages.Equals("") ? "\r\n" : "") + $"{time}\t{correlationID}\t{log}";
			});

			if (!string.IsNullOrWhiteSpace(stack))
			{
				serviceLogs.Enqueue($"==> Stack:\r\n{stack}");
				debugLogs.Enqueue($"==> Stack:\r\n{stack}");
				errorLogs.Enqueue($"==> Stack:\r\n{stack}");
				messages += (!messages.Equals("") ? "\r\n" : "") + $"==> Stack:\r\n{stack}";
			}

			// write files
			if (serviceLogs.Count >= this.MaxItems)
				Task.Run(() => this.FlushLogsAsync(name + sufix, serviceLogs)).ConfigureAwait(false);

			if (debugLogs.Count >= this.MaxItems)
				Task.Run(() => this.FlushLogsAsync(name + ".debugs", debugLogs)).ConfigureAwait(false);

			if (errorLogs.Count > 0)
				Task.Run(() => this.FlushLogsAsync(name + sufix + ".errors", errorLogs)).ConfigureAwait(false);

			// update to controller
			Global.OnLogsUpdated(serviceName, messages);
		}

		public Task WriteLogsAsync(string correlationID, string serviceName, string objectName, List<string> logs, string stack = null, CancellationToken cancellationToken = default(CancellationToken))
			=> UtilityService.ExecuteTask(() => this.WriteLogs(correlationID, serviceName, objectName, logs, stack), cancellationToken);

		public Task WriteLogAsync(string correlationID, string serviceName, string objectName, string log, string stack = null, CancellationToken cancellationToken = default(CancellationToken))
			=> this.WriteLogsAsync(correlationID, serviceName, objectName, new List<string>() { log }, stack, cancellationToken);

		async Task FlushLogsAsync(string name, ConcurrentQueue<string> logs)
		{
			while (this.IsFlushing)
				await Task.Delay(UtilityService.GetRandomNumber(123, 456)).ConfigureAwait(false);

			this.IsFlushing = true;
			var lines = new List<string>();
			while (logs.TryDequeue(out string log))
				lines.Add(log);
			if (lines.Count > 0)
				try
				{
					var filename = $"{DateTime.Now.ToString("yyyyMMdd")}_{name}.{DateTime.Now.ToString("HH")}.txt";
					await UtilityService.WriteTextFileAsync(Path.Combine(LoggingService.LogsPath, filename), lines, true, null, this.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch { }
			this.IsFlushing = false;
		}

		internal void FlushAllLogs()
			=> Task.Run(() => this.Logs.ForEachAsync((kvp, cancellationToken) => this.FlushLogsAsync(kvp.Key, kvp.Value), CancellationToken.None, true, false)).ConfigureAwait(false);
	}
}