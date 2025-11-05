#region Related components
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public partial class MainForm : Form
	{
		public MainForm()
			=> this.InitializeComponent();

		void MainForm_Load(object sender, EventArgs args)
			=> this.StartAsync().Execute();

		private void MainForm_FormClosed(object sender, FormClosedEventArgs args)
			=> this.Stop();

		void ManageServices_Click(object sender, EventArgs args)
			=> this.OpenServicesManager();

		void ClearLogs_Click(object sender, EventArgs args)
			=> this.CleanLogs();

		async Task StartAsync()
		{
			await Task.Delay(UtilityService.GetRandomNumber(123, 456)).ConfigureAwait(false);
			Program.Start();
			await Task.Delay(UtilityService.GetRandomNumber(3456, 6789)).ConfigureAwait(false);
			await Program.Manager.SendInterCommunicateMessageAsync("Controller#RequestInfo").ConfigureAwait(false);
			await Program.Manager.SendInterCommunicateMessageAsync("Service#RequestInfo").ConfigureAwait(false);
		}

		void Stop()
			=> Program.Stop();

		void OpenServicesManager()
		{
			if (Program.Controller.State == ServiceState.Ready || Program.Controller.State == ServiceState.Connected)
			{
				Program.ManagementForm = Program.ManagementForm ?? new ManagementForm();
				Program.ManagementForm.DisplayServices();
				Program.ManagementForm.Show();
				Program.ManagementForm.Focus();
			}
		}

		public delegate void UpdateLogsDelegator(string logs);

		public delegate void UpdateServicesInfoDelegator();

		void CleanLogs()
			=> this.Logs.Text = "";

		internal void UpdateLogs(string logs)
		{
			if (!this.IsDisposed && !string.IsNullOrWhiteSpace(logs))
				try
				{
					if (base.InvokeRequired)
						base.Invoke(new UpdateLogsDelegator(this.UpdateLogs), new object[] { logs });
					else
					{
						this.Logs.AppendText(logs + "\r\n");
						this.Logs.SelectionStart = this.Logs.TextLength;
						this.Logs.ScrollToCaret();
					}
				}
				catch { }
		}

		internal void UpdateServicesInfo()
		{
			if (!this.IsDisposed)
				try
				{
					if (base.InvokeRequired)
						base.Invoke(new UpdateServicesInfoDelegator(this.UpdateServicesInfo), new object[] { });
					else
						this.ServicesInfo.Text = $"Available services: {Program.Manager.AvailableServices.Count:#,##0} - Running services: {Program.Manager.AvailableServices.Where(kvp => kvp.Value.FirstOrDefault(svc => svc.Running) != null).Count():#,##0}";
				}
				catch { }
		}
	}
}