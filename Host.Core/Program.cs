namespace net.vieapps.Services.APIGateway
{
	class Program
	{
		static void Main(string[] args) => new ServiceHosting().Run(args);
	}

	class ServiceHosting : ServiceHostingBase
	{
		protected override void PrepareServiceType()
		{
			base.PrepareServiceType();
			this.ServiceType = this.ServiceType ?? Components.Utility.AssemblyLoader.GetType(System.IO.Path.Combine(System.AppDomain.CurrentDomain.BaseDirectory, $"{this.ServiceAssemblyName}.dll"), this.ServiceTypeName);
		}
	}
}