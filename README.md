# Services.APIGateway

## Main parts:

- Router: for routing messages of all microservices and controllers/managers
- Controller: for managing all microservices on one node
- Http: public APIs of all microservices, incorporation with both HTTP RESTful or WebSocket (JSON messages with RESTful style)

## Supporting parts:

- Host: for hosting all microservices on one node
- Watcher: for watching the running states of router, controller, ...
- Bundles: for bundling all required components in one task

## Others:

- Messaging protocol: WAMP-proto with WampSharp
- Authentication mechanisim: JSON Web Token
- .NET Standard 2.0