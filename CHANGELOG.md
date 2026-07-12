# Changelog

## [0.6.0](https://github.com/groundsgg/service-permissions/compare/v0.5.0...v0.6.0) (2026-07-12)


### Features

* support global permission snapshot sync ([#30](https://github.com/groundsgg/service-permissions/issues/30)) ([a365068](https://github.com/groundsgg/service-permissions/commit/a3650689e8c41d285392dd0a31339538b1cf74d9))

## [0.5.0](https://github.com/groundsgg/service-permissions/compare/v0.4.0...v0.5.0) (2026-07-11)


### Features

* **permissions:** expose role aggregate data ([#29](https://github.com/groundsgg/service-permissions/issues/29)) ([6c09832](https://github.com/groundsgg/service-permissions/commit/6c098323060e325188e4e67d17f2f10c6f51b015))


### Bug Fixes

* **ci:** publish the image for bare `v*` release tags ([#27](https://github.com/groundsgg/service-permissions/issues/27)) ([5b32a80](https://github.com/groundsgg/service-permissions/commit/5b32a80c0198bfc380f8c644f7a89fe0219476a5))

## [0.4.0](https://github.com/groundsgg/service-permissions/compare/v0.3.0...v0.4.0) (2026-07-11)


### Features

* add permissions policy engine ([9dacceb](https://github.com/groundsgg/service-permissions/commit/9daccebb6c691c3dd51e5da1fb494d7438d873c6))
* add permissions rest api ([#6](https://github.com/groundsgg/service-permissions/issues/6)) ([15b7c22](https://github.com/groundsgg/service-permissions/commit/15b7c228f19b91019e2bba4e37ccc014b83ff7d2))
* add permissions schema ([28dd002](https://github.com/groundsgg/service-permissions/commit/28dd002209925106e0c626d1cdeaac11b015721e))
* expose permissions grpc api ([bcc0d60](https://github.com/groundsgg/service-permissions/commit/bcc0d6012272e5cadc69365887f320a85267f953))
* generate Minecraft permission role keys ([#22](https://github.com/groundsgg/service-permissions/issues/22)) ([04972d3](https://github.com/groundsgg/service-permissions/commit/04972d3e89b56260c54e14f344345d5ac0858a44))
* **permissions:** expose role aggregate counts ([#26](https://github.com/groundsgg/service-permissions/issues/26)) ([a57189e](https://github.com/groundsgg/service-permissions/commit/a57189ed67628502df4450f4e40b89e518c848f6))
* persist permission manifests ([#20](https://github.com/groundsgg/service-permissions/issues/20)) ([e7bdb62](https://github.com/groundsgg/service-permissions/commit/e7bdb624435140daecbdadac967530381fd265da))
* prepare permissions service for platform tests ([c4acc47](https://github.com/groundsgg/service-permissions/commit/c4acc477206eefb399dced4efc60f3d21a375a24))
* prepare permissions service for platform tests ([c35a9af](https://github.com/groundsgg/service-permissions/commit/c35a9af98f14db71264fc327122a75dcb6ffd85e))
* protect permissions rest api ([#9](https://github.com/groundsgg/service-permissions/issues/9)) ([7c80a32](https://github.com/groundsgg/service-permissions/commit/7c80a329a146b743c61ea548900932ef5ec49ec5))
* scaffold permissions service ([e2d3a88](https://github.com/groundsgg/service-permissions/commit/e2d3a888b876680edba64a5f8004c41792983808))


### Bug Fixes

* avoid mutable production policy provider ([79b2acd](https://github.com/groundsgg/service-permissions/commit/79b2acdfcf69400fab8a2f8ebba5126763094404))
* cap permission snapshot expiry ([727bb5f](https://github.com/groundsgg/service-permissions/commit/727bb5fac25423b15efe2333a49b6cd437fbeab9))
* fail closed on expired permission snapshots ([e93b605](https://github.com/groundsgg/service-permissions/commit/e93b6055c7e69864802a2949a3870c65b0e10530))
* index permissions schema lookups ([43b85ee](https://github.com/groundsgg/service-permissions/commit/43b85eecfd55f3349a68035bca9ab55842f0e4de))
* **permissions:** authorize project permissions editors ([#12](https://github.com/groundsgg/service-permissions/issues/12)) ([80c63e9](https://github.com/groundsgg/service-permissions/commit/80c63e9a4bc90edf2b7c8f19fbc43d67459b519a))
* **permissions:** trust forge project role context ([#16](https://github.com/groundsgg/service-permissions/issues/16)) ([dee2326](https://github.com/groundsgg/service-permissions/commit/dee23269b0d8d5533b1e90a9be094854ca54abed))
* read project permission headers case-insensitively ([#14](https://github.com/groundsgg/service-permissions/issues/14)) ([e1bb82e](https://github.com/groundsgg/service-permissions/commit/e1bb82ed140bbeee61e1df35966fbc0283f0c749))
* reject invalid permission manifest scopes ([80409eb](https://github.com/groundsgg/service-permissions/commit/80409eb096fd51b875c8e2c290ac704e90851a9e))
* **release:** omit component name from tags ([#24](https://github.com/groundsgg/service-permissions/issues/24)) ([5c8d325](https://github.com/groundsgg/service-permissions/commit/5c8d3252ccfb0931299ea2cb0fa88cddd0e835a8))
* scope direct player permission grants ([b0a5724](https://github.com/groundsgg/service-permissions/commit/b0a5724efa3e05bd7a1be6ae8f549780ba8e3de7))
* validate permissions grpc requests ([4ff0131](https://github.com/groundsgg/service-permissions/commit/4ff01316aec7ea537ecd73d530b35f5c808fb333))

## [0.3.0](https://github.com/groundsgg/service-permissions/compare/service-permissions-v0.2.0...service-permissions-v0.3.0) (2026-07-10)


### Features

* generate Minecraft permission role keys ([#22](https://github.com/groundsgg/service-permissions/issues/22)) ([04972d3](https://github.com/groundsgg/service-permissions/commit/04972d3e89b56260c54e14f344345d5ac0858a44))

## [0.2.0](https://github.com/groundsgg/service-permissions/compare/service-permissions-v0.1.3...service-permissions-v0.2.0) (2026-07-09)


### Features

* persist permission manifests ([#20](https://github.com/groundsgg/service-permissions/issues/20)) ([e7bdb62](https://github.com/groundsgg/service-permissions/commit/e7bdb624435140daecbdadac967530381fd265da))

## [0.1.3](https://github.com/groundsgg/service-permissions/compare/service-permissions-v0.1.2...service-permissions-v0.1.3) (2026-07-07)


### Bug Fixes

* **permissions:** trust forge project role context ([#16](https://github.com/groundsgg/service-permissions/issues/16)) ([dee2326](https://github.com/groundsgg/service-permissions/commit/dee23269b0d8d5533b1e90a9be094854ca54abed))

## [0.1.2](https://github.com/groundsgg/service-permissions/compare/service-permissions-v0.1.1...service-permissions-v0.1.2) (2026-07-07)


### Bug Fixes

* read project permission headers case-insensitively ([#14](https://github.com/groundsgg/service-permissions/issues/14)) ([e1bb82e](https://github.com/groundsgg/service-permissions/commit/e1bb82ed140bbeee61e1df35966fbc0283f0c749))

## [0.1.1](https://github.com/groundsgg/service-permissions/compare/service-permissions-v0.1.0...service-permissions-v0.1.1) (2026-07-06)


### Bug Fixes

* **permissions:** authorize project permissions editors ([#12](https://github.com/groundsgg/service-permissions/issues/12)) ([80c63e9](https://github.com/groundsgg/service-permissions/commit/80c63e9a4bc90edf2b7c8f19fbc43d67459b519a))

## [0.1.0](https://github.com/groundsgg/service-permissions/compare/service-permissions-v0.0.1...service-permissions-v0.1.0) (2026-06-30)


### Features

* add permissions policy engine ([9dacceb](https://github.com/groundsgg/service-permissions/commit/9daccebb6c691c3dd51e5da1fb494d7438d873c6))
* add permissions rest api ([#6](https://github.com/groundsgg/service-permissions/issues/6)) ([15b7c22](https://github.com/groundsgg/service-permissions/commit/15b7c228f19b91019e2bba4e37ccc014b83ff7d2))
* add permissions schema ([28dd002](https://github.com/groundsgg/service-permissions/commit/28dd002209925106e0c626d1cdeaac11b015721e))
* expose permissions grpc api ([bcc0d60](https://github.com/groundsgg/service-permissions/commit/bcc0d6012272e5cadc69365887f320a85267f953))
* prepare permissions service for platform tests ([c4acc47](https://github.com/groundsgg/service-permissions/commit/c4acc477206eefb399dced4efc60f3d21a375a24))
* prepare permissions service for platform tests ([c35a9af](https://github.com/groundsgg/service-permissions/commit/c35a9af98f14db71264fc327122a75dcb6ffd85e))
* protect permissions rest api ([#9](https://github.com/groundsgg/service-permissions/issues/9)) ([7c80a32](https://github.com/groundsgg/service-permissions/commit/7c80a329a146b743c61ea548900932ef5ec49ec5))
* scaffold permissions service ([e2d3a88](https://github.com/groundsgg/service-permissions/commit/e2d3a888b876680edba64a5f8004c41792983808))


### Bug Fixes

* avoid mutable production policy provider ([79b2acd](https://github.com/groundsgg/service-permissions/commit/79b2acdfcf69400fab8a2f8ebba5126763094404))
* cap permission snapshot expiry ([727bb5f](https://github.com/groundsgg/service-permissions/commit/727bb5fac25423b15efe2333a49b6cd437fbeab9))
* fail closed on expired permission snapshots ([e93b605](https://github.com/groundsgg/service-permissions/commit/e93b6055c7e69864802a2949a3870c65b0e10530))
* index permissions schema lookups ([43b85ee](https://github.com/groundsgg/service-permissions/commit/43b85eecfd55f3349a68035bca9ab55842f0e4de))
* reject invalid permission manifest scopes ([80409eb](https://github.com/groundsgg/service-permissions/commit/80409eb096fd51b875c8e2c290ac704e90851a9e))
* scope direct player permission grants ([b0a5724](https://github.com/groundsgg/service-permissions/commit/b0a5724efa3e05bd7a1be6ae8f549780ba8e3de7))
* validate permissions grpc requests ([4ff0131](https://github.com/groundsgg/service-permissions/commit/4ff01316aec7ea537ecd73d530b35f5c808fb333))
