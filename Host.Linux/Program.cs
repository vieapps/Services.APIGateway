using System;
using System.Runtime.InteropServices;

namespace net.vieapps.Services.APIGateway
{
    class Program
    {
		static HostComponent Component = new HostComponent();

		static void Main(string[] args)
        {
			Program.Component.Start(args);
		}
    }
}
