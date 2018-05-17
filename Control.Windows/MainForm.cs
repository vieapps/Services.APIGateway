using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

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
			Program.CancellationTokenSource = new CancellationTokenSource();
			Program.Component = new ControlComponent(Program.CancellationTokenSource.Token);
			Program.Component.Start(this._args, async () =>
			{
				await Task.Delay(1234).ConfigureAwait(false);
				var serviceManager = Program.GetServiceManager();
				if (serviceManager != null)
				{
					var services = serviceManager.GetAvailableBusinessServices();
					services.Select(kvp => kvp.Key).ToList().ForEach(name => services[name] = serviceManager.IsBusinessServiceRunning(name) ? "Yes" : "No");
					this.UpdateServicesInfo(services.Count, services.Where(kvp => kvp.Value.Equals("Yes")).Count());
				}
			});
		}

		void MainForm_FormClosed(object sender, FormClosedEventArgs args)
		{
			Program.Component.Dispose();
			Program.CancellationTokenSource.Cancel();
			Program.CancellationTokenSource.Dispose();
		}

		void ManageServices_Click(object sender, EventArgs args)
		{
			if (Program.Component.Status.Equals("Ready"))
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

		public delegate void UpdateServicesInfoDelegator(int available, int running);

		internal void UpdateServicesInfo(int available, int running)
		{
			if (base.InvokeRequired)
				base.Invoke(new UpdateServicesInfoDelegator(this.UpdateServicesInfo), new object[] { available, running });
			else
				try
				{
					this.ServicesInfo.Text = $"Available services: {available} - Running services: {running}";
				}
				catch { }
		}
	}
}