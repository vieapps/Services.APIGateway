#region Related components
using System;
using System.Linq;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Collections.Generic;

using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public partial class ManagementForm : Form
	{
		public ManagementForm()
		{
			this.InitializeComponent();
			this.ServiceURI.Text = "Service URI";
			this.ServiceStatus.Text = "Status";
			this.Services.MultiSelect = false;
		}

		void ServicesForm_FormClosing(object sender, FormClosingEventArgs e)
		{
			this.SetControlsState(false, false);
			this.Selected = null;
			this.Hide();
			e.Cancel = true;
		}

		void Services_SelectedIndexChanged(object sender, EventArgs e) => this.OnSelected();

		void Change_Click(object sender, EventArgs e) => this.OnChange();

		public delegate void DisplayServicesDelegator();

		internal void DisplayServices()
		{
			if (base.InvokeRequired)
				base.Invoke(new DisplayServicesDelegator(this.DisplayServices), new object[] { });
			else
			{
				var gotMultipleInstances = false;
				foreach (var kvp in Program.Manager.AvailableServices)
					if (kvp.Value.Count > 1)
					{
						gotMultipleInstances = true;
						break;
					}

				this.Services.Items.Clear();
				Program.Manager.AvailableServices.OrderBy(kvp => kvp.Key).ForEach(kvp =>
				{
					var name = kvp.Key;
					var info = kvp.Value.Where(serviceInfo => serviceInfo.Available).ToList();
					if (gotMultipleInstances)
					{
						var isRunning = info.FirstOrDefault(serviceInfo => serviceInfo.Running) != null;
						var itemOfAll = new ListViewItem(new[] { $"services.{name} - {info.Count:#,##0} instance(s)", isRunning ? "Running" : "Stopped", "", name })
						{
							UseItemStyleForSubItems = false
						};
						itemOfAll.SubItems[0].Font = new Font(this.Services.Font, FontStyle.Bold);
						itemOfAll.SubItems[1].ForeColor = isRunning ? SystemColors.WindowText : Color.Red;
						this.Services.Items.Add(itemOfAll);

						info.ForEach(serviceInfo =>
						{
							if (Program.Manager.AvailableControllers.TryGetValue(serviceInfo.ControllerID, out ControllerInfo controller))
							{
								var itemOfController = new ListViewItem(new[] { $"  {controller.Host} - {controller.Platform}", serviceInfo.Running ? "Running" : "Stopped", controller.ID, name })
								{
									UseItemStyleForSubItems = false
								};
								itemOfController.SubItems[1].ForeColor = serviceInfo.Running ? SystemColors.WindowText : Color.Red;
								this.Services.Items.Add(itemOfController);
							}
						});
					}
					else if (info.Count > 0)
					{
						var serviceInfo = info[0];
						if (Program.Manager.AvailableControllers.TryGetValue(serviceInfo.ControllerID, out ControllerInfo controller))
						{
							var listItem = new ListViewItem(new[] { $"services.{name}", serviceInfo.Running ? "Running" : "Stopped", controller.ID, name })
							{
								UseItemStyleForSubItems = false
							};
							listItem.SubItems[1].ForeColor = serviceInfo.Running ? SystemColors.WindowText : Color.Red;
							this.Services.Items.Add(listItem);
						}
					}
				});
			}
		}

		public delegate void SetControlsStateDelegator(bool state, bool servicesApplied);

		internal void SetControlsState(bool state, bool servicesApplied = true)
		{
			if (base.InvokeRequired)
				base.Invoke(new SetControlsStateDelegator(this.SetControlsState), new object[] { state, servicesApplied });
			else
			{
				this.ServiceName.Visible = this.Change.Enabled = state && this.Selected != null;
				if (servicesApplied)
					this.Services.Enabled = state;
			}
		}

		public delegate void OnSelectedDelegator();

		void OnSelected()
		{
			if (base.InvokeRequired)
				base.Invoke(new OnSelectedDelegator(this.OnSelected), new object[] { });
			else
			{
				if (this.Services.SelectedItems == null || this.Services.SelectedItems.Count < 1)
					this.SetControlsState(false, false);
				else
				{
					this.Selected = this.Services.SelectedItems[0];
					this.DisplaySelectedService();
				}
			}
		}

		internal ListViewItem Selected { get; set; } = null;

		bool IsSelectAllControllers => this.Selected != null ? this.Selected.SubItems[2].Text.Equals("") : false;

		public delegate void DisplaySelectedServiceDelegator();

		void DisplaySelectedService()
		{
			if (base.InvokeRequired)
				base.Invoke(new DisplaySelectedServiceDelegator(this.DisplaySelectedService), new object[] { });
			else
			{
				var name = this.Selected.SubItems[3].Text;
				var isSelectAllControllers = this.IsSelectAllControllers;
				var isRunning = isSelectAllControllers
					? Program.Manager.AvailableServices[name].Where(svc => svc.Running).Count() > 0
					: this.Selected.SubItems[1].Text.Equals("Running");

				this.SetControlsState(true);
				this.Change.Text = isRunning ? "Stop" : "Start";
				if (isSelectAllControllers)
					this.ServiceName.Text = $"services.{name} - All instances";
				else
				{
					var controller = Program.Manager.AvailableControllers[this.Selected.SubItems[2].Text];
					this.ServiceName.Text = $"{name} @ {controller.Host} [{controller.Platform}]";
				}
			}
		}

		void OnChange()
		{
			if (this.Selected == null)
				return;

			var name = this.Selected.SubItems[3].Text;
			if (!this.IsSelectAllControllers)
			{
				this.SetControlsState(false);
				var controllerID = this.Selected.SubItems[2].Text;
				if (this.Selected.SubItems[1].Text.Equals("Running"))
					Task.Run(() => Program.Manager.StopBusinessService(controllerID, name)).ConfigureAwait(false);
				else
					Task.Run(() => Program.Manager.StartBusinessService(controllerID, name, Program.Controller.GetServiceArguments().Replace("/", "/call-"))).ConfigureAwait(false);
			}
			else if (MessageBox.Show($"Are you sure you want to {(Program.Manager.AvailableServices[name].Where(svc => svc.Running).Count() > 0 ? "stop" : "start")} all instances of the \"{name}\" service?", "Service", MessageBoxButtons.YesNo) == DialogResult.Yes)
			{
				this.SetControlsState(false);
				if (Program.Manager.AvailableServices[name].Where(svc => svc.Running).Count() > 0)
					Program.Manager.AvailableControllers.Keys.ForEach(controllerID => Task.Run(() => Program.Manager.StopBusinessService(controllerID, name)).ConfigureAwait(false));
				else
				{
					var svcArgs = Program.Controller.GetServiceArguments().Replace("/", "/call-");
					Program.Manager.AvailableControllers.Keys.ForEach(controllerID => Task.Run(() => Program.Manager.StartBusinessService(controllerID, name, svcArgs)).ConfigureAwait(false));
				}
			}

			this.SetControlsState(true);
			this.Services.Select();
		}

		public delegate void RedisplayServiceDelegator(string controllerID, string name, string state);

		internal void RedisplayService(string controllerID, string name, string state)
		{
			if (base.InvokeRequired)
				base.Invoke(new RedisplayServiceDelegator(this.RedisplayService), new object[] { controllerID, name, state });
			else
			{
				ListViewItem listItem = null;
				foreach (ListViewItem item in this.Services.Items)
					if (item.SubItems[2].Text.Equals(controllerID) && item.SubItems[3].Text.Equals(name))
					{
						listItem = item;
						break;
					}
				if (listItem != null)
				{
					listItem.SubItems[1].Text = state;
					listItem.SubItems[1].ForeColor = state.IsEquals("Running") ? SystemColors.WindowText : Color.Red;
				}

				foreach (ListViewItem item in this.Services.Items)
					if (item.SubItems[2].Text.Equals("") && item.SubItems[3].Text.Equals(name))
					{
						listItem = item;
						break;
					}
				if (listItem != null)
				{
					var isRunning = Program.Manager.AvailableServices[name].FirstOrDefault(svc => svc.Running) != null;
					listItem.SubItems[1].Text = isRunning ? "Running" : "Stopped";
					listItem.SubItems[1].ForeColor = isRunning ? SystemColors.WindowText : Color.Red;
				}

				this.Services.Select();
				if (this.Selected != null)
					this.DisplaySelectedService();
			}
		}
	}
}