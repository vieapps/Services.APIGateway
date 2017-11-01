# Services.APIGateway
The API Gateway of all microservices in the VIEApps NGX with three parts:
- Http: public API Gateway with REST & WebSocket (real-time update)
- Control: provide services to centralized managing microservices
- Host: provide hosting container for all microservices

Others:
- Messaging protocol: WAMP-proto with WampSharp
- Authentication mechanisim: JSON Web Token
- .NET Standard 2.0