# service-permissions

Central authorization service for the Grounds Minecraft platform. It manages the permission catalog, roles, player and Keycloak group grants, identity synchronization, and permission policy transfer between environments through REST and gRPC APIs.

## Development

Run the service in Quarkus development mode:

```bash
./gradlew quarkusDev
```

Run the test suite, formatter, and build:

```bash
./gradlew test
./gradlew spotlessApply
./gradlew build
```

See the [in-game permissions documentation](https://docs.grounds.gg/reference/plugins/in-game-permissions) for the permission model, administration, infrastructure, and runtime integration.

## License

Licensed under the [GNU Affero General Public License v3.0](LICENSE). The Grounds licensing model is documented at [docs.grounds.gg/licensing](https://docs.grounds.gg/licensing).
