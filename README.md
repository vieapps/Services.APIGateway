# Services.APIGateway

## Main parts:

- Router: for routing messages of all microservices and controllers/managers
- Controller: for managing all microservices on one node
- Http: public APIs of all microservices, expose as RESTful API or WebSocket API (JSON messages with REST style)

## Supporting parts:

- Host: for hosting all microservices on one node
- Watcher: for watching the running states of router, controller, ...
- Bundles: for bundling all required components in one task

## Others:

- Messaging protocol: WAMP-proto with WampSharp, support routed RPC and Pub/Sub with multiple instances
- Authentication mechanisim: JWT (JSON Web Token)
