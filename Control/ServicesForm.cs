#region Related components
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public partial class ServicesForm : Form
	{
		public ServicesForm()
		{
			this.InitializeComponent();
		}

		Dictionary<string, bool> _businessServices = null;

		void ServicesForm_Load(object sender, EventArgs e)
		{
			if (Global.ServiceManager == null)
				Global.ServiceManager = Global.Component._outgoingChannel.RealmProxy.Services.GetCalleeProxy<IServiceManager>(ProxyInterceptor.Create());
		}

		void ServicesForm_FormClosing(object sender, FormClosingEventArgs e)
		{
			this.Hide();
			e.Cancel = true;
		}

		internal void Initialize()
		{
			this.ServiceName.Text = "Service";
			this.ServiceStatus.Text = "Status";
			this.Services.MultiSelect = false;

			this.RefreshServices();
			this.DisplayServices();
		}

		internal void RefreshServices()
		{
			if (Global.ServiceManager == null)
				Global.ServiceManager = Global.Component._outgoingChannel.RealmProxy.Services.GetCalleeProxy<IServiceManager>(ProxyInterceptor.Create());

			this._businessServices = new Dictionary<string, bool>();
			Global.ServiceManager.GetAvailableBusinessServices().ForEach(kvp => this._businessServices.Add($"net.vieapps.services.{kvp.Key}", Global.ServiceManager.IsBusinessServiceRunning(kvp.Key)));
		}

		void DisplayServices()
		{
			this.Services.Items.Clear();
			this._businessServices.ForEach(kvp => this.Services.Items.Add(new ListViewItem(new[] { kvp.Key, kvp.Value ? "Running" : "Stopped" })));
			Global.MainForm.UpdateServicesInfo(this._businessServices.Count, this._businessServices.Where(kvp => kvp.Value).Count());
		}

		void Services_SelectedIndexChanged(object sender, EventArgs e)
		{
			if (this.Services.SelectedItems == null || this.Services.SelectedItems.Count < 1)
			{
				this.Service.Visible = this.Change.Enabled = false;
				return;
			}

			this.Service.Visible = this.Change.Enabled = true;
			this.Service.Text = $"Service: [{this.Services.SelectedItems[0].Text}";
			this.Change.Text = this._businessServices[this.Services.SelectedItems[0].Text]
				? "Stop"
				: "Start";
		}

		void Change_Click(object sender, EventArgs e)
		{
			if (this.Services.SelectedItems == null || this.Services.SelectedItems.Count < 1)
				return;

			var name = this.Services.SelectedItems[0].Text;
			if (this._businessServices[name])
				Task.Run(() =>
				{
					try
					{
						Global.ServiceManager.StopBusinessService(name.ToArray('.').Last());
						this._businessServices[name] = false;
					}
					catch (Exception ex)
					{
						Global.WriteLog($"Error occurred while stopping a business service: {ex.Message}", ex);
					}
				})
				.ContinueWith(task =>
				{
					this.DisplayServices();
				});
			else
				Task.Run(() =>
				{
					try
					{
						Global.ServiceManager.StartBusinessService(name.ToArray('.').Last());
						this._businessServices[name] = true;
					}
					catch (Exception ex)
					{
						Global.WriteLog($"Error occurred while starting a business service: {ex.Message}", ex);
					}
				})
				.ContinueWith(task =>
				{
					this.DisplayServices();
				});
		}
	}
}
