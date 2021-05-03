namespace net.vieapps.Services.APIGateway
{
	partial class ServiceRunner
	{
		System.ComponentModel.IContainer _component = null;

		protected override void Dispose(bool disposing)
		{
			if (disposing && (this._component != null))
				this._component.Dispose();
			base.Dispose(disposing);
		}

		void InitializeComponent()
		{
			this._component = new System.ComponentModel.Container();
			this.ServiceName = "VIEApps-APIGateway-Controller";
		}
	}
}
