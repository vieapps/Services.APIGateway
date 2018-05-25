using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using net.vieapps.Components.Utility;

namespace net.vieapps.Services.APIGateway
{
	public partial class MainForm : Form
	{
		string[] _args = null;

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
				Program.Start(this._args, async () =>
				{
					await Task.Delay(1234).ConfigureAwait(false);
					Program.PrepareServices();
					this.UpdateServicesInfo();
				});
			}).ConfigureAwait(false);
		}

		private void MainForm_FormClosed(object sender, FormClosedEventArgs args) => Program.Stop();

		void ManageServices_Click(object sender, EventArgs args)
		{
			if (Program.Component.State == ServiceState.Ready || Program.Component.State == ServiceState.Connected)
			{
				Program.ManagementForm = Program.ManagementForm ?? new ManagementForm();
				Program.ManagementForm.Initialize();
				Program.ManagementForm.Show();
				Program.ManagementForm.Focus();
			}
		}

		void ClearLogs_Click(object sender, EventArgs args) => this.Logs.Text = "";

		public delegate void UpdateLogsDelegator(string logs);

		internal void UpdateLogs(string logs)
		{
			if (base.InvokeRequired)
				base.Invoke(new UpdateLogsDelegator(this.UpdateLogs), new object[] { logs });
			else
				try
				{
					this.Logs.AppendText(logs + "\r\n");
					this.Logs.SelectionStart = this.Logs.TextLength;
					this.Logs.ScrollToCaret();
				}
				catch { }
		}

		public delegate void UpdateServicesInfoDelegator();

		internal void UpdateServicesInfo()
		{
			if (base.InvokeRequired)
				base.Invoke(new UpdateServicesInfoDelegator(this.UpdateServicesInfo), new object[] { });
			else
				this.ServicesInfo.Text = $"Available services: {Program.Services.Count} - Running services: {Program.Services.Where(svc => svc.Value).Count()}";
		}
	}
}