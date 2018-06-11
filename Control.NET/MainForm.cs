#region Related components
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Collections.Generic;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public partial class MainForm : Form
	{
		readonly string[] _args;

		public MainForm(string[] args = null)
		{
			this.InitializeComponent();
			this._args = args;
		}

		void MainForm_Load(object sender, EventArgs args)
		{
			Task.Run(async () =>
			{
				await Task.Delay(UtilityService.GetRandomNumber(123, 456)).ConfigureAwait(false);
				Program.Start(this._args);
				await Task.Delay(UtilityService.GetRandomNumber(3456, 6789)).ConfigureAwait(false);
				await Program.Manager.SendInterCommunicateMessageAsync("Controller#RequestInfo").ConfigureAwait(false);
				await Program.Manager.SendInterCommunicateMessageAsync("Service#RequestInfo").ConfigureAwait(false);
			}).ConfigureAwait(false);
		}

		private void MainForm_FormClosed(object sender, FormClosedEventArgs args) => Program.Stop();

		void ManageServices_Click(object sender, EventArgs args)
		{
			if (Program.Controller.State == ServiceState.Ready || Program.Controller.State == ServiceState.Connected)
			{
				Program.ManagementForm = Program.ManagementForm ?? new ManagementForm();
				Program.ManagementForm.DisplayServices();
				Program.ManagementForm.Show();
				Program.ManagementForm.Focus();
			}
		}

		void ClearLogs_Click(object sender, EventArgs args) => this.Logs.Text = "";

		public delegate void UpdateLogsDelegator(string logs);

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

		public delegate void UpdateServicesInfoDelegator();

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