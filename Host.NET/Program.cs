namespace net.vieapps.Services.APIGateway
{
	static class Program
	{
		static void Main(string[] args) => new ServiceHosting().Run(args);
	}

	class ServiceHosting : ServiceHost
	{
		protected override void PrepareServiceType() => base.PrepareServiceType();
	}
}