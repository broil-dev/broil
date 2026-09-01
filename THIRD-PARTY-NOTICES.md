# Third-Party Notices

This generated notice applies only to the `broil` 0.1.0 executable for
`x86_64-unknown-linux-gnu`. It is not a generic or cross-target notice.

## Closure identity

- Release version: `v0.1.0`.
- Root `Cargo.lock` SHA-256: `62f989cb2d5983b36fe6a56348ff65724a063314bb5560a9daa9c29d8556a8b9`.
- Binary root: `broil 0.1.0`.
- Target: `x86_64-unknown-linux-gnu`.
- Selected locked normal closure: 162 packages (6 first-party trace packages and 156 third-party packages).
- Filter: Cargo normal dependency edges and their resolved features only; build, development, and test-only edges and feature requests are excluded.
- Evidence commands:
  - `cargo metadata --locked --offline --format-version 1 --filter-platform x86_64-unknown-linux-gnu`
  - `cargo tree --locked --offline --package broil --target x86_64-unknown-linux-gnu --edges normal --prefix none --format '{p}|{f}'`
- The full package, source/checksum or path-identity, resolved-feature, manifest, and legal-material ledger is `docs/dev/third-party-notices/x86_64-unknown-linux-gnu-closure.tsv`.
- First-party trace packages are retained only to make the selected binary closure auditable: `broil`, `broil-cli`, `broil-command`, `broil-config`, `broil-core`, and `broil-remote`. They are not third-party notice entries.

## Package inventory

| Package | Declared license | Source identity |
| --- | --- | --- |
| aead 0.6.1 | MIT OR Apache-2.0 | crates.io checksum: `1973cfbc1a2daf9cf550e74e1f088c28e7f7d8c1e1418fb6c9dc5184b7e84c99` |
| aes 0.9.2 | MIT OR Apache-2.0 | crates.io checksum: `f8eb277bec05f56a0e0591f155a484cbd0f4f07ff2905051a48c72f004f7ed58` |
| aes-gcm 0.11.0 | Apache-2.0 OR MIT | crates.io checksum: `fdf011db2e21ce0d575593d749db5554b47fed37aff429e4dc50bc91ac93a028` |
| argon2 0.6.0-rc.8 | MIT OR Apache-2.0 | crates.io checksum: `7af50940b73bf4e16c15c448a2b121c63f2d68e3e54b6a8731673cb4aa0cdff5` |
| arraydeque 0.5.1 | MIT/Apache-2.0 | crates.io checksum: `7d902e3d592a523def97af8f317b08ce16b7ab854c1985a0c671e6f15cebc236` |
| base16ct 1.0.0 | Apache-2.0 OR MIT | crates.io checksum: `fd307490d624467aa6f74b0eabb77633d1f758a7b25f12bceb0b22e08d9726f6` |
| base64ct 1.8.3 | Apache-2.0 OR MIT | crates.io checksum: `2af50177e190e07a26ab74f8b1efbfe2ef87da2116221318cb1c2e82baf7de06` |
| bcrypt-pbkdf 0.11.0 | MIT OR Apache-2.0 | crates.io checksum: `144e573728da132683b9488acd528274c790e07fc06ff81ee29f9d8f8b1041e0` |
| bitflags 2.13.1 | MIT OR Apache-2.0 | crates.io checksum: `b588b76d00fde79687d7646a9b5bdf3cc0f655e0bbd080335a95d7e96f3587da` |
| blake2 0.11.0-rc.6 | MIT OR Apache-2.0 | crates.io checksum: `061f1a09225e328e1ffbb378d2d49923c0ca5fee19fb5ac1cc9c1e9d52b93690` |
| block-buffer 0.12.1 | MIT OR Apache-2.0 | crates.io checksum: `d2f6c7dbe95a6ed67ad9f18e57daf93a2f034c524b99fd2b76d18fdfeb6660aa` |
| block-padding 0.4.2 | MIT OR Apache-2.0 | crates.io checksum: `710f1dd022ef4e93f8a438b4ba958de7f64308434fa6a87104481645cc30068b` |
| blowfish 0.10.0 | MIT OR Apache-2.0 | crates.io checksum: `62ce3946557b35e71d1bbe07ec385073ce9eda05043f95de134eb578fcf1a298` |
| byteorder 1.5.0 | Unlicense OR MIT | crates.io checksum: `1fd0f2584146f6f2ef48085050886acf353beff7305ebd1ae69500e27c67f64b` |
| bytes 1.12.1 | MIT | crates.io checksum: `fc652a48c352aef3ea3aed32080501cf3ef6ed5da78602a020c991775b0aff04` |
| cbc 0.2.1 | MIT OR Apache-2.0 | crates.io checksum: `ce2dc9ee5f88d11e0beb842c88b33c8a5cf0d1329c4b19494af42b07dbfe8896` |
| cfg-if 1.0.4 | MIT OR Apache-2.0 | crates.io checksum: `9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801` |
| chacha20 0.10.1 | MIT OR Apache-2.0 | crates.io checksum: `d524456ba66e72eb8b115ff89e01e497f8e6d11d78b70b1aa13c0fbd97540a81` |
| chrono 0.4.45 | MIT OR Apache-2.0 | crates.io checksum: `1aa79e62e7697b8e29b513a68abacf485adcd1fe8284a4316c5ae868e6633327` |
| cipher 0.5.2 | MIT OR Apache-2.0 | crates.io checksum: `e8cf2a2c93cd704877c0858356ed03480ff301ee950b43f1cbe4573b088bfa6c` |
| cmov 0.5.4 | Apache-2.0 OR MIT | crates.io checksum: `0c9ea0ac24bc397ab3c98583a3c9ba74fa56b09a4449bbe172b9b1ddb016027a` |
| const-oid 0.10.2 | Apache-2.0 OR MIT | crates.io checksum: `a6ef517f0926dd24a1582492c791b6a4818a4d94e789a334894aa15b0d12f55c` |
| cpubits 0.1.1 | MIT OR Apache-2.0 | crates.io checksum: `15b85f9c39137c3a891689859392b1bd49812121d0d61c9caf00d46ed5ce06ae` |
| cpufeatures 0.3.0 | MIT OR Apache-2.0 | crates.io checksum: `8b2a41393f66f16b0823bb79094d54ac5fbd34ab292ddafb9a0456ac9f87d201` |
| crossbeam-utils 0.8.22 | MIT OR Apache-2.0 | crates.io checksum: `61803da095bee82a81bb1a452ecc25d3b2f1416d1897eb86430c6159ef717c17` |
| crypto-bigint 0.7.5 | Apache-2.0 OR MIT | crates.io checksum: `1a52aa3fcda4e6302a9f48734f234d35d4721b96f8fe07d073f07ce9df4f0271` |
| crypto-common 0.2.2 | MIT OR Apache-2.0 | crates.io checksum: `ce6e4c961d6cd6c9a86db418387425e8bdeaf05b3c8bc1411e6dca4c252f1453` |
| ctr 0.10.1 | MIT OR Apache-2.0 | crates.io checksum: `baaca1c4b237092596f64d571e9db6ce4109c4ef9742e27590f1709594461f21` |
| ctutils 0.4.2 | Apache-2.0 OR MIT | crates.io checksum: `7d5515a3834141de9eafb9717ad39eea8247b5674e6066c404e8c4b365d2a29e` |
| curve25519-dalek 5.0.0 | BSD-3-Clause | crates.io checksum: `b5eed333089e2e1c1ac8c6c0398e5e2497b4c9926ca6d0365ed1e099afa5bc23` |
| curve25519-dalek-derive 0.1.1 | MIT/Apache-2.0 | crates.io checksum: `f46882e17999c6cc590af592290432be3bce0428cb0d5f8b6715e4dc7b383eb3` |
| dashmap 6.2.1 | MIT | crates.io checksum: `e6361d5c062261c78a176addb82d4c821ae42bed6089de0e12603cd25de2059c` |
| data-encoding 2.11.1 | MIT | crates.io checksum: `4583a4551df46e2792f82ceeac45e850d2e2d5debba0b91f102385cda5b11f06` |
| delegate 0.13.5 | MIT OR Apache-2.0 | crates.io checksum: `780eb241654bf097afb00fc5f054a09b687dad862e485fdcf8399bb056565370` |
| der 0.8.1 | Apache-2.0 OR MIT | crates.io checksum: `a69dedd701da44b0536442edf09c81a64b0ab97a7a4a5e3d1971f00027cbc63d` |
| digest 0.11.3 | MIT OR Apache-2.0 | crates.io checksum: `f1dd6dbb5841937940781866fa1281a1ff7bd3bf827091440879f9994983d5c2` |
| ecdsa 0.17.0 | Apache-2.0 OR MIT | crates.io checksum: `c0681a4fc24c767085329728d8dfba959af91228aa4610cca4f8ce317ba46ae0` |
| ed25519 3.0.0 | Apache-2.0 OR MIT | crates.io checksum: `29fcf32e6c73d1079f83ab4d782de2d81620346a5f38c6237a86a22f8368980a` |
| ed25519-dalek 3.0.0 | BSD-3-Clause | crates.io checksum: `6ebaa1a2bf1290ab3bfe5a7b771d050ebffab2711c19a81691c683a5144a25de` |
| elliptic-curve 0.14.1 | Apache-2.0 OR MIT | crates.io checksum: `9d65aa39b3a5c1c9c1b745c9a019234bb7a21b77abcb4f4d266d706e2d577d65` |
| encoding_rs 0.8.35 | (Apache-2.0 OR MIT) AND BSD-3-Clause | crates.io checksum: `75030f3c4f45dafd7586dd6780965a8c7e8e285a5ecb86713e63a79c5b2766f3` |
| enum_dispatch 0.3.13 | MIT OR Apache-2.0 | crates.io checksum: `aa18ce2bc66555b3218614519ac839ddb759a7d6720732f979ef8d13be147ecd` |
| errno 0.3.14 | MIT OR Apache-2.0 | crates.io checksum: `39cab71617ae0d63f51a36d69f866391735b51691dbda63cf6f96d042b63efeb` |
| fastrand 2.5.0 | Apache-2.0 OR MIT | crates.io checksum: `da7c62ceae207dd37ea5b845da6a0696c799f85e97da1ab5b7910be3c1c80223` |
| ff 0.14.0 | MIT/Apache-2.0 | crates.io checksum: `a1f686ab92a9fb0eaf188f6c6c87b89490baa6fdb0db4544ba4dc47f7942489f` |
| foldhash 0.2.0 | Zlib | crates.io checksum: `77ce24cb58228fbb8aa041425bb1050850ac19177686ea6e0f41a70416f56fdb` |
| futures 0.3.33 | MIT OR Apache-2.0 | crates.io checksum: `a88cf1f829d945f548cf8fec32c61b1f202b6d93b45848602fc02af4b12ad218` |
| futures-channel 0.3.33 | MIT OR Apache-2.0 | crates.io checksum: `262590f4fe6afeb0bc83be1daa64e52657fe185690a958af7f3ad0e92085c5ae` |
| futures-core 0.3.33 | MIT OR Apache-2.0 | crates.io checksum: `2cd50c473c80f6d7c3670a752354b8e569b1a7cbfdc0419ec88e5edad85e0dc7` |
| futures-executor 0.3.33 | MIT OR Apache-2.0 | crates.io checksum: `6754879cc9f2c66f88c6e5c35344bb0bdb0708b0352b1201815667c7eabc7458` |
| futures-io 0.3.33 | MIT OR Apache-2.0 | crates.io checksum: `4577ecaa3c4f96589d473f679a71b596316f6641bc350038b962a5daf0085d7a` |
| futures-macro 0.3.33 | MIT OR Apache-2.0 | crates.io checksum: `2d6d3cde68c518367be28956066ddfef33813991b77a55005a69dae04bf3b10b` |
| futures-sink 0.3.33 | MIT OR Apache-2.0 | crates.io checksum: `e34418ac499d6305c2fb5ad0ed2f6ac998c5f8ca209b4510f7f94242c647e307` |
| futures-task 0.3.33 | MIT OR Apache-2.0 | crates.io checksum: `b231ed28831efb4a61a08580c4bc233ec56bc009f4cd8f52da2c3cb97df0c109` |
| futures-util 0.3.33 | MIT OR Apache-2.0 | crates.io checksum: `a77a90a256fce34da66415271e30f94ee91c57b04b8a2c042d9cf3220179deaa` |
| generic-array 0.14.9 | MIT | crates.io checksum: `4bb6743198531e02858aeaea5398fcc883e71851fcbcb5a2f773e2fb6cb1edf2` |
| generic-array 1.4.4 | MIT | crates.io checksum: `ab4e5aa225bc56696909483320f0ff9b600f1a971b52e07a17d70f3d9b43254b` |
| getrandom 0.2.17 | MIT OR Apache-2.0 | crates.io checksum: `ff2abc00be7fca6ebc474524697ae276ad847ad0a6b3faa4bcb027e9a4614ad0` |
| getrandom 0.4.3 | MIT OR Apache-2.0 | crates.io checksum: `300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099` |
| ghash 0.6.0 | Apache-2.0 OR MIT | crates.io checksum: `2eecf2d5dc9b66b732b97707a0210906b1d30523eb773193ab777c0c84b3e8d5` |
| group 0.14.0 | MIT/Apache-2.0 | crates.io checksum: `7fd1a1c7a5206c5b7a3f5a0d7ccd3ff85d0c8f5133d62a02680255b0004af5f4` |
| hashbrown 0.14.5 | MIT OR Apache-2.0 | crates.io checksum: `e5274423e17b7c9fc20b6e7e208532f9b19825d82dfd615708b70edd83df41f1` |
| hashbrown 0.17.1 | MIT OR Apache-2.0 | crates.io checksum: `ed5909b6e89a2db4456e54cd5f673791d7eca6732202bbf2a9cc504fe2f9b84a` |
| hashlink 0.12.1 | MIT OR Apache-2.0 | crates.io checksum: `32069d97bb81e38fa67eab65e3393bf804bb85969f2bc06bf13f64aef5aba248` |
| hex 0.4.3 | MIT OR Apache-2.0 | crates.io checksum: `7f24254aa9a54b5c858eaee2f5bccdb46aaf0e486a595ed5fd8f86ba55232a70` |
| hex-literal 1.1.0 | MIT OR Apache-2.0 | crates.io checksum: `e712f64ec3850b98572bffac52e2c6f282b29fe6c5fa6d42334b30be438d95c1` |
| hkdf 0.13.0 | MIT OR Apache-2.0 | crates.io checksum: `4aaa26c720c68b866f2c96ef5c1264b3e6f473fe5d4ce61cd44bbe913e553018` |
| hmac 0.13.0 | MIT OR Apache-2.0 | crates.io checksum: `6303bc9732ae41b04cb554b844a762b4115a61bfaa81e3e83050991eeb56863f` |
| hybrid-array 0.4.14 | MIT OR Apache-2.0 | crates.io checksum: `707114b52a152fa7bdb290cd7cd5912d9467273b6d74e21b8d81aca1f8533f6b` |
| iana-time-zone 0.1.65 | MIT OR Apache-2.0 | crates.io checksum: `e31bc9ad994ba00e440a8aa5c9ef0ec67d5cb5e5cb0cc7f8b744a35b389cc470` |
| inout 0.2.2 | MIT OR Apache-2.0 | crates.io checksum: `4250ce6452e92010fdf7268ccc5d14faa80bb12fc741938534c58f16804e03c7` |
| internal-russh-num-bigint 0.5.0 | MIT OR Apache-2.0 | crates.io checksum: `ae8e22120c32fb4d19ec55fba35015f57095cd95a2e3b732e44457f5915b2ee8` |
| itoa 1.0.18 | MIT OR Apache-2.0 | crates.io checksum: `8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682` |
| keccak 0.2.1 | Apache-2.0 OR MIT | crates.io checksum: `ffd9697dc4a9a62e2da93389f34400b77a28f0287711263cabb203b3ccb9c0e4` |
| kem 0.3.0 | Apache-2.0 OR MIT | crates.io checksum: `01737161ba802849cfd486b5bd209d38ba4943494c249a8126005170c7621edd` |
| libc 0.2.189 | MIT OR Apache-2.0 | crates.io checksum: `3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2` |
| linux-raw-sys 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | crates.io checksum: `32a66949e030da00e8c7d4434b251670a91556f4144941d37452769c25d58a53` |
| lock_api 0.4.14 | MIT OR Apache-2.0 | crates.io checksum: `224399e74b87b5f3557511d98dff8b14089b3dadafcab6bb93eab67d3aace965` |
| log 0.4.33 | MIT OR Apache-2.0 | crates.io checksum: `0ceec5bc11778974d1bcb055b18002eba7f4b3518b6a0081b3af5f21666da9ad` |
| md5 0.8.1 | Apache-2.0 OR MIT | crates.io checksum: `7ebb8d8732c6a6df3d8f032a82911cfc747e00efb95cc46e8d0acd5b5b88570c` |
| memchr 2.8.3 | Unlicense OR MIT | crates.io checksum: `cf8baf1c55e62ffcace7a9f06f4bd9cd3f0c4beb022d3b367256b91b87513d98` |
| mio 1.2.2 | MIT | crates.io checksum: `30d65c71f1ce40ab09135ce117d742b9f8a19ff91a41a8b57ed50bc2de59c427` |
| ml-kem 0.3.2 | Apache-2.0 OR MIT | crates.io checksum: `5e15f3e5b957493873e396a66914e83e616b6afe335cdef7efe5c6e1216aba66` |
| module-lattice 0.2.3 | Apache-2.0 OR MIT | crates.io checksum: `0c61b87c9683ab7cb1c6871d261ad5479b6b10ceb52c4352aaca3b5d35a8febe` |
| nix 0.31.3 | MIT | crates.io checksum: `cf20d2fde8ff38632c426f1165ed7436270b44f199fc55284c38276f9db47c3d` |
| num-bigint 0.4.8 | MIT OR Apache-2.0 | crates.io checksum: `c89e69e7e0f03bea5ef08013795c25018e101932225a656383bd384495ecc367` |
| num-integer 0.1.46 | MIT OR Apache-2.0 | crates.io checksum: `7969661fd2958a5cb096e56c8e1ad0444ac2bbcd0061bd28660485a44879858f` |
| num-traits 0.2.19 | MIT OR Apache-2.0 | crates.io checksum: `071dfc062690e90b734c0b2273ce72ad0ffa95f0c74596bc250dcfd960262841` |
| once_cell 1.21.4 | MIT OR Apache-2.0 | crates.io checksum: `9f7c3e4beb33f85d45ae3e3a1792185706c8e16d043238c593331cc7cd313b50` |
| ordered-float 5.3.0 | MIT | crates.io checksum: `b7d950ca161dc355eaf28f82b11345ed76c6e1f6eb1f4f4479e0323b9e2fbd0e` |
| p256 0.14.0 | Apache-2.0 OR MIT | crates.io checksum: `d2c9239b2dbc807adbbe147e8cf72ea7450c3a0aabe62cb8e75ff4ec22e1f72a` |
| p384 0.14.0 | Apache-2.0 OR MIT | crates.io checksum: `d17b851e6b3e378ab4ecb07fa2ed23f4d15f075735f8fec9fa1e7bdce5f8301f` |
| p521 0.14.0 | Apache-2.0 OR MIT | crates.io checksum: `4ad64cc32c2dc466317c12ee5853e61f159f9eab1fe7efade0395dc2e7b43449` |
| parking_lot_core 0.9.12 | MIT OR Apache-2.0 | crates.io checksum: `2621685985a2ebf1c516881c026032ac7deafcda1a2c9b7850dc81e3dfcb64c1` |
| pbkdf2 0.13.0 | MIT OR Apache-2.0 | crates.io checksum: `112d82ceb8c5bf524d9af484d4e4970c9fd5a0cc15ba14ad93dccd28873b0629` |
| pem-rfc7468 1.0.0 | Apache-2.0 OR MIT | crates.io checksum: `a6305423e0e7738146434843d1694d621cce767262b2a86910beab705e4493d9` |
| pin-project-lite 0.2.17 | Apache-2.0 OR MIT | crates.io checksum: `a89322df9ebe1c1578d689c92318e070967d1042b512afbe49518723f4e6d5cd` |
| pkcs5 0.8.1 | Apache-2.0 OR MIT | crates.io checksum: `63d440a804ec8d6fafbb6b84471e013286658d373248927692ab3366686220ca` |
| pkcs8 0.11.0 | Apache-2.0 OR MIT | crates.io checksum: `451913da69c775a56034ea8d9003d27ee8948e12443eae7c038ba100a4f21cb7` |
| poly1305 0.9.1 | Apache-2.0 OR MIT | crates.io checksum: `6e2d0073b297041425c7c3df6eb4792d598a15323fe63346852b092eca02904c` |
| polyval 0.7.3 | Apache-2.0 OR MIT | crates.io checksum: `f0fa31d631f2b2cb2a544d0aa321ce847a94764d701ca2becc411138b93d49cd` |
| primefield 0.14.0 | Apache-2.0 OR MIT | crates.io checksum: `c555a6e4eb7d4e158fcb028c835c3b8642206ddc279b5c6b202ef9a8bdb592f4` |
| primeorder 0.14.0 | Apache-2.0 OR MIT | crates.io checksum: `5c9f42978c78a00e3d68f69fc03e57a234debae69da4020a4fb588fcdcd07b06` |
| proc-macro2 1.0.107 | MIT OR Apache-2.0 | crates.io checksum: `985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9` |
| quote 1.0.47 | MIT OR Apache-2.0 | crates.io checksum: `1fbf4db142a473a8d80c26bbf18454ed458bf8d26c8219c331daecfdbd079001` |
| rand 0.10.2 | MIT OR Apache-2.0 | crates.io checksum: `c7f5fa3a058cd35567ef9bfa5e75732bee0f9e4c55fa90477bef2dfcdbc4be80` |
| rand_core 0.10.1 | MIT OR Apache-2.0 | crates.io checksum: `63b8176103e19a2643978565ca18b50549f6101881c443590420e4dc998a3c69` |
| rfc6979 0.6.0 | Apache-2.0 OR MIT | crates.io checksum: `b4a459cddafb3fe76b31fd8f1108007566c40301feb64dc7b54656eb7388172b` |
| ring 0.17.14 | Apache-2.0 AND ISC | crates.io checksum: `a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7` |
| russh 0.62.5 | Apache-2.0 | vendored path: `path+file://$REPO_ROOT/crates/vendor/russh-0.62.5#russh@0.62.5` |
| russh-cryptovec 0.62.0 | Apache-2.0 | crates.io checksum: `3aec6cb630dbe85d72ffd7bcd95f07e1bd69f9f270ee8adfa1afe443a6331438` |
| russh-sftp 2.4.0 | Apache-2.0 | crates.io checksum: `9de67aace74530a29086db0671fa200c470a58eb380081f28ad512ffb0c5356b` |
| russh-util 0.52.0 | Apache-2.0 | crates.io checksum: `668424a5dde0bcb45b55ba7de8476b93831b4aa2fa6947e145f3b053e22c60b6` |
| rustix 1.1.4 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | crates.io checksum: `b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190` |
| rustversion 1.0.23 | MIT OR Apache-2.0 | crates.io checksum: `cf54715a573b99ac80df0bc206da022bcd442c974952c7b9720069370852e21f` |
| salsa20 0.11.0 | MIT OR Apache-2.0 | crates.io checksum: `2f874456e72520ff1375a06c588eaf074b0f01f9e9e1aada45bd9b7954a6e42c` |
| saphyr 0.0.11 | MIT OR Apache-2.0 | crates.io checksum: `8acd6cfc4803660d26a3fb5bd8f5e47bc0eea5229f4d32f7cb4ee21a733e6961` |
| saphyr-parser 0.0.11 | MIT OR Apache-2.0 | crates.io checksum: `ebfd783fcf1b3f6bafd557be0e1427ec54f826f513c3cdd749f9844484df2a13` |
| scopeguard 1.2.0 | MIT OR Apache-2.0 | crates.io checksum: `94143f37725109f92c262ed2cf5e59bce7498c01bcc1502d7b9afe439a4e9f49` |
| scrypt 0.12.0 | MIT OR Apache-2.0 | crates.io checksum: `d87af57419b594aa23fa95f09f0e06d80d84ba01c26148c43844cad6ff4485f0` |
| sec1 0.8.1 | Apache-2.0 OR MIT | crates.io checksum: `d56d437c2f19203ce5f7122e507831de96f3d2d4d3be5af44a0b0a09d8a80e4d` |
| serde 1.0.229 | MIT OR Apache-2.0 | crates.io checksum: `4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba` |
| serde_bytes 0.11.19 | MIT OR Apache-2.0 | crates.io checksum: `a5d440709e79d88e51ac01c4b72fc6cb7314017bb7da9eeff678aa94c10e3ea8` |
| serde_core 1.0.229 | MIT OR Apache-2.0 | crates.io checksum: `67dca2c9c51e58a4791a4b1ed58308b39c64224d349a935ab5039aa360942a48` |
| serde_derive 1.0.229 | MIT OR Apache-2.0 | crates.io checksum: `e7a5d71263a5a7d47b41f6b3f06ba276f10cc18b0931f1799f710578e2309348` |
| serde_json 1.0.151 | MIT OR Apache-2.0 | crates.io checksum: `c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14` |
| sha1 0.11.0 | MIT OR Apache-2.0 | crates.io checksum: `aacc4cc499359472b4abe1bf11d0b12e688af9a805fa5e3016f9a386dc2d0214` |
| sha2 0.11.0 | MIT OR Apache-2.0 | crates.io checksum: `446ba717509524cb3f22f17ecc096f10f4822d76ab5c0b9822c5f9c284e825f4` |
| sha3 0.11.0 | MIT OR Apache-2.0 | crates.io checksum: `be176f1a57ce4e3d31c1a166222d9768de5954f811601fb7ca06fc8203905ce1` |
| sha3 0.12.0 | MIT OR Apache-2.0 | crates.io checksum: `bc9bad02c26382724b2d2692c6f179285e4b54eeecd7968f52a50059c3c11759` |
| signal-hook-registry 1.4.8 | MIT OR Apache-2.0 | crates.io checksum: `c4db69cba1110affc0e9f7bcd48bbf87b3f4fc7c61fc9155afd4c469eb3d6c1b` |
| signature 3.0.0 | Apache-2.0 OR MIT | crates.io checksum: `28d567dcbaf0049cb8ac2608a76cd95ff9e4412e1899d389ee400918ca7537f5` |
| slab 0.4.12 | MIT | crates.io checksum: `0c790de23124f9ab44544d7ac05d60440adc586479ce501c1d6d7da3cd8c9cf5` |
| smallvec 1.15.2 | MIT OR Apache-2.0 | crates.io checksum: `8ed6a63f02c8539c91a8685a86f4099661ba3da017932f6ebbea6de3f0fa7c90` |
| socket2 0.6.5 | MIT OR Apache-2.0 | crates.io checksum: `c3d1e2c7f27f8d4cb10542a02c49005dbd6e93095799d6f3be745fae9f8fedd4` |
| spki 0.8.0 | Apache-2.0 OR MIT | crates.io checksum: `1d9efca8738c78ee9484207732f728b1ef517bbb1833d6fc0879ca898a522f6f` |
| sponge-cursor 0.1.0 | MIT OR Apache-2.0 | crates.io checksum: `3a0219bd7d979d58245a4f41f695e1ac9f8befdffadd7f61f1bae9e39abc6620` |
| ssh-cipher 0.3.0 | Apache-2.0 OR MIT | crates.io checksum: `d801accda99469cde6d73da741422610fdf6508a72d9a69d1b55cb241c720597` |
| ssh-encoding 0.3.0 | Apache-2.0 OR MIT | crates.io checksum: `7b54d0ed0498daf3f78d82e00e28c8eec9d75a067c4cfbcc7a0f7d0f4077749e` |
| ssh-key 0.7.0-rc.11 | Apache-2.0 OR MIT | crates.io checksum: `f9a32fae177b74a22aa9c5b01bf7e68b33545be32d9e381e248058d2adc15ce3` |
| subtle 2.6.1 | BSD-3-Clause | crates.io checksum: `13c2bddecc57b384dee18652358fb23172facb8a2c51ccc10d74c157bdea3292` |
| syn 2.0.119 | MIT OR Apache-2.0 | crates.io checksum: `872831b642d1a07999a962a351ed35b955ea2cfc8f3862091e2a240a84f17297` |
| syn 3.0.3 | MIT OR Apache-2.0 | crates.io checksum: `53e9bae58849f64dfa4f5d5ae372c8341f7305f82a3868709269343628b659a3` |
| tempfile 3.27.0 | MIT OR Apache-2.0 | crates.io checksum: `32497e9a4c7b38532efcdebeef879707aa9f794296a4f0244f6f69e9bc8574bd` |
| thiserror 2.0.19 | MIT OR Apache-2.0 | crates.io checksum: `09a43598840e33d5b0331f38c5e30d13bb11c11210a4b58f0d9b18a5a5eefcd9` |
| thiserror-impl 2.0.19 | MIT OR Apache-2.0 | crates.io checksum: `43cbfe0cf76104d42a574802844187e84a305e531ed54455f11fbde0f10541cd` |
| tokio 1.53.1 | MIT | crates.io checksum: `202caea871b69668250d242070849eb495be178ed697a3e98aebce5bc81a0bed` |
| tokio-macros 2.7.2 | MIT | crates.io checksum: `78773a2a397f451582ce068015985c33193cf6dea8b74d2a639fe457b2f07b0e` |
| tokio-util 0.7.19 | MIT | crates.io checksum: `494815d09bf52b5548659851081238f0ca39ff638363907596da739561c62c52` |
| typenum 1.20.1 | MIT OR Apache-2.0 | crates.io checksum: `b6f5e870be6c3b371b77fe0ee0bafb859fa4964b4404c27de1d380043c4dda20` |
| unicode-ident 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 | crates.io checksum: `e6e4313cd5fcd3dad5cafa179702e2b244f760991f45397d14d4ebf38247da75` |
| universal-hash 0.6.1 | MIT OR Apache-2.0 | crates.io checksum: `f4987bdc12753382e0bec4a65c50738ffaabc998b9cdd1f952fb5f39b0048a96` |
| untrusted 0.9.0 | ISC | crates.io checksum: `8ecb6da28b8a351d773b68d5825ac39017e680750f980f3a1a85cd8dd28a47c1` |
| wnaf 0.14.0 | Apache-2.0 OR MIT | crates.io checksum: `ab12e7090f27e2ffd9322651492942d50c2926094af30601e1964337db39daf1` |
| zeroize 1.9.0 | Apache-2.0 OR MIT | crates.io checksum: `e13c156562582aa81c60cb29407084cdb54c4164760106ab78e6c5b0858cf64e` |
| zmij 1.0.23 | MIT | crates.io checksum: `29666d0abbfad1e3dc4dcf6144730dd3a3ab225bbbdac83319345b1b44ccfc1b` |

## Legal-text handling

The ledger records every current package manifest license declaration and every inspected source legal-material input (`LICENSE*`, `COPYING*`, `COPYRIGHT*`, `NOTICE*`, `AUTHORS*`, `ATTRIBUTION*`, `ACKNOWLEDGEMENTS*`, `PATENTS*`, and `UNLICENSE*`). This notice retains each source-specific copyright, attribution, and notice text below and deduplicates common full license terms by reproducing one current source copy per represented license family. Packages with dual-license expressions retain both represented standard terms below; no package license expression is rewritten.

No selected package supplied a file named `NOTICE*`; source-specific `COPYRIGHT*` and acknowledgement inputs are reproduced below. The three packages with no named legal file (`delegate 0.13.5`, `russh-cryptovec 0.62.0`, and `russh-util 0.52.0`) are represented by their recorded manifest license declarations and the corresponding retained full license terms.

## Vendored Russh provenance

- Package: `russh 0.62.5` at `crates/vendor/russh-0.62.5/`; Git tree identity for this vendored package: `8aa6b2d53df8d22feba6692f6d4e4491f736a296`.
- Its own `LICENSE.txt` is retained below (SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`).
- Provenance: `docs/provenance/russh-0.62.5.md` (SHA-256 `b4fbe6adea73641e3f76bf39f10cdf4d829304be66b6b509e32c6ee02d31fa1a`). The historical `docs/dev/ssh-hardening-evidence/production-closure.tsv` is supplemental provenance only; it is not this notice’s closure record.
- The six existing Broil modification notices remain in the vendored tree, with their comments updated only to point at the release-carried `docs/provenance/russh-0.62.5.md` provenance record:
  - `crates/vendor/russh-0.62.5/src/auth.rs`
  - `crates/vendor/russh-0.62.5/src/client/encrypted.rs`
  - `crates/vendor/russh-0.62.5/src/client/mod.rs`
  - `crates/vendor/russh-0.62.5/src/keys/format/mod.rs`
  - `crates/vendor/russh-0.62.5/src/keys/format/pkcs5.rs`
  - `crates/vendor/russh-0.62.5/src/keys/mod.rs`

```text
// Modified by the Broil project from russh 0.62.5; see LICENSE.txt and docs/provenance/russh-0.62.5.md for provenance.
```
## Source-specific copyright and attribution notices

### aead 0.6.1


### aes 0.9.2

- `LICENSE-MIT`: Copyright (c) 2018 Artyom Pavlov
- `LICENSE-MIT`: Copyright (c) 2018-2024 The RustCrypto Project Developers

### aes-gcm 0.11.0

- `LICENSE-MIT`: Copyright (c) 2019-2026 The RustCrypto Project Developers

### argon2 0.6.0-rc.8

- `LICENSE-MIT`: Copyright (c) 2021-2024 The RustCrypto Project Developers

### arraydeque 0.5.1

- `LICENSE`: Copyright (c) 2018 Andy Lok <andylokandy@hotmail.com>

### base16ct 1.0.0

- `LICENSE-MIT`: Copyright (c) 2014 Steve "Sc00bz" Thomas (steve at tobtu dot com)
- `LICENSE-MIT`: Copyright (c) 2022-2025 The RustCrypto Project Developers

### base64ct 1.8.3

- `LICENSE-MIT`: Copyright (c) 2014 Steve "Sc00bz" Thomas (steve at tobtu dot com)
- `LICENSE-MIT`: Copyright (c) 2021-2025 The RustCrypto Project Developers

### bcrypt-pbkdf 0.11.0

- `LICENSE-MIT`: Copyright (c) 2019 Jack Grigg
- `LICENSE-MIT`: Copyright (c) 2019-2026 The RustCrypto Project Developers

### bitflags 2.13.1

- `LICENSE-MIT`: Copyright (c) 2014 The Rust Project Developers

### blake2 0.11.0-rc.6

- `LICENSE-MIT`: Copyright (c) 2015-2016 The blake2-rfc Developers, Cesar Barros
- `LICENSE-MIT`: Copyright (c) 2017 Artyom Pavlov
- `LICENSE-MIT`: Copyright (c) 2017-2026 The RustCrypto Project Developers

### block-buffer 0.12.1

- `LICENSE-MIT`: Copyright (c) 2018-2025 The RustCrypto Project Developers

### block-padding 0.4.2

- `LICENSE-MIT`: Copyright (c) 2018-2025 The RustCrypto Project Developers

### blowfish 0.10.0

- `LICENSE-MIT`: Copyright (c) 2016-2024 The RustCrypto Project Developers

### byteorder 1.5.0

- `LICENSE-MIT`: Copyright (c) 2015 Andrew Gallant

### bytes 1.12.1

- `LICENSE`: Copyright (c) 2018 Carl Lerche

### cbc 0.2.1

- `LICENSE-MIT`: Copyright (c) 2018 Artyom Pavlov
- `LICENSE-MIT`: Copyright (c) 2018-2022 RustCrypto Developers

### cfg-if 1.0.4

- `LICENSE-MIT`: Copyright (c) 2014 Alex Crichton

### chacha20 0.10.1

- `LICENSE-MIT`: Copyright (c) 2019-2026 The RustCrypto Project Developers

### chrono 0.4.45

- `LICENSE.txt`: Copyright (c) 2014, Kang Seonghoon.

### cipher 0.5.2

- `LICENSE-MIT`: Copyright (c) 2016-2025 RustCrypto Developers

### cmov 0.5.4

- `LICENSE-MIT`: Copyright (c) 2022-2026 The RustCrypto Project Developers

### const-oid 0.10.2

- `LICENSE-MIT`: Copyright (c) 2020-2026 The RustCrypto Project Developers

### cpubits 0.1.1

- `LICENSE-MIT`: Copyright (c) 2023-2026 The RustCrypto Project Developers

### cpufeatures 0.3.0

- `LICENSE-MIT`: Copyright (c) 2020-2025 The RustCrypto Project Developers

### crossbeam-utils 0.8.22

- `LICENSE-MIT`: Copyright (c) 2019 The Crossbeam Project Developers

### crypto-bigint 0.7.5

- `LICENSE-MIT`: Copyright (c) 2021-2026 The RustCrypto Project Developers

### crypto-common 0.2.2

- `LICENSE-MIT`: Copyright (c) 2021-2026 RustCrypto Developers

### ctr 0.10.1

- `LICENSE-MIT`: Copyright (c) 2018 Artyom Pavlov
- `LICENSE-MIT`: Copyright (c) 2018-2022 RustCrypto Developers

### ctutils 0.4.2

- `LICENSE-MIT`: Copyright (c) 2025-2026 The RustCrypto Project Developers

### curve25519-dalek-derive 0.1.1


### dashmap 6.2.1

- `LICENSE`: Copyright (c) 2019 Acrimon

### data-encoding 2.11.1

- `LICENSE`: Copyright (c) 2015-2020 Julien Cretin
- `LICENSE`: Copyright (c) 2017-2020 Google Inc.

### der 0.8.1

- `LICENSE-MIT`: Copyright (c) 2020-2026 The RustCrypto Project Developers

### digest 0.11.3

- `LICENSE-MIT`: Copyright (c) 2017 Artyom Pavlov
- `LICENSE-MIT`: Copyright (c) 2017-2025 RustCrypto Developers

### ecdsa 0.17.0

- `LICENSE-APACHE`: Copyright 2018-2022 RustCrypto Developers
- `LICENSE-MIT`: Copyright (c) 2018-2026 RustCrypto Developers

### ed25519 3.0.0

- `LICENSE-APACHE`: Copyright 2018-2022 RustCrypto Developers
- `LICENSE-MIT`: Copyright (c) 2018-2026 RustCrypto Developers

### ed25519-dalek 3.0.0

- `LICENSE`: Copyright (c) 2017-2019 isis agora lovecruft. All rights reserved.

### elliptic-curve 0.14.1

- `LICENSE-MIT`: Copyright (c) 2020-2026 RustCrypto Developers

### encoding_rs 0.8.35

- `LICENSE-MIT`: Copyright Mozilla Foundation

### enum_dispatch 0.3.13

- `LICENSE`: Copyright (c) 2019 Anton Lazarev

### errno 0.3.14

- `LICENSE-MIT`: Copyright (c) 2014 Chris Wong

### fastrand 2.5.0


### ff 0.14.0

- `LICENSE-MIT`: Copyright (c) 2017 Sean Bowe

### futures 0.3.33

- `LICENSE-APACHE`: Copyright (c) 2016 Alex Crichton
- `LICENSE-APACHE`: Copyright (c) 2017 The Tokio Authors
- `LICENSE-MIT`: Copyright (c) 2016 Alex Crichton
- `LICENSE-MIT`: Copyright (c) 2017 The Tokio Authors

### futures-channel 0.3.33

- `LICENSE-APACHE`: Copyright (c) 2016 Alex Crichton
- `LICENSE-APACHE`: Copyright (c) 2017 The Tokio Authors
- `LICENSE-MIT`: Copyright (c) 2016 Alex Crichton
- `LICENSE-MIT`: Copyright (c) 2017 The Tokio Authors

### futures-core 0.3.33

- `LICENSE-APACHE`: Copyright (c) 2016 Alex Crichton
- `LICENSE-APACHE`: Copyright (c) 2017 The Tokio Authors
- `LICENSE-MIT`: Copyright (c) 2016 Alex Crichton
- `LICENSE-MIT`: Copyright (c) 2017 The Tokio Authors

### futures-executor 0.3.33

- `LICENSE-APACHE`: Copyright (c) 2016 Alex Crichton
- `LICENSE-APACHE`: Copyright (c) 2017 The Tokio Authors
- `LICENSE-MIT`: Copyright (c) 2016 Alex Crichton
- `LICENSE-MIT`: Copyright (c) 2017 The Tokio Authors

### futures-io 0.3.33

- `LICENSE-APACHE`: Copyright (c) 2016 Alex Crichton
- `LICENSE-APACHE`: Copyright (c) 2017 The Tokio Authors
- `LICENSE-MIT`: Copyright (c) 2016 Alex Crichton
- `LICENSE-MIT`: Copyright (c) 2017 The Tokio Authors

### futures-macro 0.3.33

- `LICENSE-APACHE`: Copyright (c) 2016 Alex Crichton
- `LICENSE-APACHE`: Copyright (c) 2017 The Tokio Authors
- `LICENSE-MIT`: Copyright (c) 2016 Alex Crichton
- `LICENSE-MIT`: Copyright (c) 2017 The Tokio Authors

### futures-sink 0.3.33

- `LICENSE-APACHE`: Copyright (c) 2016 Alex Crichton
- `LICENSE-APACHE`: Copyright (c) 2017 The Tokio Authors
- `LICENSE-MIT`: Copyright (c) 2016 Alex Crichton
- `LICENSE-MIT`: Copyright (c) 2017 The Tokio Authors

### futures-task 0.3.33

- `LICENSE-APACHE`: Copyright (c) 2016 Alex Crichton
- `LICENSE-APACHE`: Copyright (c) 2017 The Tokio Authors
- `LICENSE-MIT`: Copyright (c) 2016 Alex Crichton
- `LICENSE-MIT`: Copyright (c) 2017 The Tokio Authors

### futures-util 0.3.33

- `LICENSE-APACHE`: Copyright (c) 2016 Alex Crichton
- `LICENSE-APACHE`: Copyright (c) 2017 The Tokio Authors
- `LICENSE-MIT`: Copyright (c) 2016 Alex Crichton
- `LICENSE-MIT`: Copyright (c) 2017 The Tokio Authors

### generic-array 0.14.9

- `LICENSE`: Copyright (c) 2015 Bartłomiej Kamiński

### generic-array 1.4.4

- `LICENSE`: Copyright (c) 2015 Bartłomiej Kamiński

### getrandom 0.2.17

- `LICENSE-MIT`: Copyright (c) 2014 The Rust Project Developers
- `LICENSE-MIT`: Copyright (c) 2018-2024 The rust-random Project Developers

### getrandom 0.4.3

- `LICENSE-MIT`: Copyright (c) 2014 The Rust Project Developers
- `LICENSE-MIT`: Copyright (c) 2018-2026 The rust-random Project Developers

### ghash 0.6.0

- `LICENSE-MIT`: Copyright (c) 2019-2026 The RustCrypto Project Developers

### group 0.14.0


### hashbrown 0.14.5

- `LICENSE-MIT`: Copyright (c) 2016 Amanieu d'Antras

### hashbrown 0.17.1

- `LICENSE-MIT`: Copyright (c) 2016 Amanieu d'Antras

### hashlink 0.12.1


### hex 0.4.3

- `LICENSE-MIT`: Copyright (c) 2013-2014 The Rust Project Developers.
- `LICENSE-MIT`: Copyright (c) 2015-2020 The rust-hex Developers

### hex-literal 1.1.0

- `LICENSE-MIT`: Copyright (c) 2018 Artyom Pavlov
- `LICENSE-MIT`: Copyright (c) 2018-2025 The RustCrypto Project Developers

### hkdf 0.13.0

- `LICENSE-MIT`: Copyright (c) 2015-2018 Vlad Filippov
- `LICENSE-MIT`: Copyright (c) 2018-2021 RustCrypto Developers

### hmac 0.13.0

- `LICENSE-MIT`: Copyright (c) 2017 Artyom Pavlov

### hybrid-array 0.4.14

- `LICENSE-MIT`: Copyright (c) 2022-2026 The RustCrypto Project Developers

### iana-time-zone 0.1.65

- `LICENSE-APACHE`: Copyright 2020 Andrew Straw
- `LICENSE-MIT`: Copyright (c) 2020 Andrew D. Straw

### inout 0.2.2

- `LICENSE-MIT`: Copyright (c) 2022 Artyom Pavlov
- `LICENSE-MIT`: Copyright (c) 2022-2025 The RustCrypto Project Developers

### internal-russh-num-bigint 0.5.0

- `LICENSE-MIT`: Copyright (c) 2014 The Rust Project Developers

### itoa 1.0.18


### keccak 0.2.1

- `LICENSE-MIT`: Copyright (c) 2018-2026 The RustCrypto Project Developers

### kem 0.3.0

- `LICENSE-APACHE`: Copyright 2021 RustCrypto Developers
- `LICENSE-MIT`: Copyright (c) 2021-2026 RustCrypto Developers

### libc 0.2.189

- `LICENSE-MIT`: Copyright (c) The Rust Project Developers

### linux-raw-sys 0.12.1


### lock_api 0.4.14

- `LICENSE-MIT`: Copyright (c) 2016 The Rust Project Developers

### log 0.4.33

- `LICENSE-MIT`: Copyright (c) 2014 The Rust Project Developers

### memchr 2.8.3

- `LICENSE-MIT`: Copyright (c) 2015 Andrew Gallant

### mio 1.2.2

- `LICENSE`: Copyright (c) 2014 Carl Lerche and other MIO contributors

### ml-kem 0.3.2

- `LICENSE-MIT`: Copyright (c) 2024-2026 RustCrypto Developers

### module-lattice 0.2.3

- `LICENSE-MIT`: Copyright (c) 2024-2026 RustCrypto Developers

### nix 0.31.3

- `LICENSE`: Copyright (c) 2015 Carl Lerche + nix-rust Authors

### num-bigint 0.4.8

- `LICENSE-MIT`: Copyright (c) 2014 The Rust Project Developers

### num-integer 0.1.46

- `LICENSE-MIT`: Copyright (c) 2014 The Rust Project Developers

### num-traits 0.2.19

- `LICENSE-MIT`: Copyright (c) 2014 The Rust Project Developers

### once_cell 1.21.4


### ordered-float 5.3.0

- `LICENSE-MIT`: Copyright (c) 2015 Jonathan Reem

### p256 0.14.0

- `LICENSE-MIT`: Copyright (c) 2020-2026 RustCrypto Developers

### p384 0.14.0

- `LICENSE-MIT`: Copyright (c) 2020-2021 RustCrypto Developers

### p521 0.14.0

- `LICENSE-MIT`: Copyright (c) 2020-2026 RustCrypto Developers

### parking_lot_core 0.9.12

- `LICENSE-MIT`: Copyright (c) 2016 The Rust Project Developers

### pbkdf2 0.13.0

- `LICENSE-MIT`: Copyright (c) 2017 Artyom Pavlov
- `LICENSE-MIT`: Copyright (c) 2018-2023 The RustCrypto Project Developers

### pem-rfc7468 1.0.0

- `LICENSE-MIT`: Copyright (c) 2021-2025 The RustCrypto Project Developers

### pin-project-lite 0.2.17


### pkcs5 0.8.1

- `LICENSE-MIT`: Copyright (c) 2021-2026 The RustCrypto Project Developers

### pkcs8 0.11.0

- `LICENSE-MIT`: Copyright (c) 2020-2026 The RustCrypto Project Developers

### poly1305 0.9.1

- `LICENSE-MIT`: Copyright (c) 2015-2026 The RustCrypto Project Developers

### polyval 0.7.3

- `LICENSE-MIT`: Copyright (c) 2019-2026 The RustCrypto Project Developers

### primefield 0.14.0

- `LICENSE-MIT`: Copyright (c) 2024-2026 RustCrypto Developers

### primeorder 0.14.0

- `LICENSE-MIT`: Copyright (c) 2020-2023 RustCrypto Developers

### proc-macro2 1.0.107


### quote 1.0.47


### rand 0.10.2

- `LICENSE-MIT`: Copyright (c) 2014 The Rust Project Developers
- `LICENSE-MIT`: Copyright 2018 Developers of the Rand project

### rand_core 0.10.1

- `LICENSE-MIT`: Copyright (c) 2018-2026 The Rand Project Developers

### rfc6979 0.6.0

- `LICENSE-APACHE`: Copyright 2018-2022 RustCrypto Developers
- `LICENSE-MIT`: Copyright (c) 2018-2026 RustCrypto Developers

### ring 0.17.14


### russh-sftp 2.4.0


### rustix 1.1.4


### rustversion 1.0.23


### salsa20 0.11.0

- `LICENSE-MIT`: Copyright (c) 2019 Eric McCorkle
- `LICENSE-MIT`: Copyright (c) 2019-2026 The RustCrypto Project Developers

### scopeguard 1.2.0

- `LICENSE-MIT`: Copyright (c) 2016-2019 Ulrik Sverdrup "bluss" and scopeguard developers

### scrypt 0.12.0

- `LICENSE-MIT`: Copyright (c) 2021-2026 The RustCrypto Project Developers

### sec1 0.8.1

- `LICENSE-MIT`: Copyright (c) 2021-2026 The RustCrypto Project Developers

### serde 1.0.229


### serde_bytes 0.11.19


### serde_core 1.0.229


### serde_derive 1.0.229


### serde_json 1.0.151


### sha1 0.11.0

- `LICENSE-MIT`: Copyright (c) 2006-2009 Graydon Hoare
- `LICENSE-MIT`: Copyright (c) 2009-2013 Mozilla Foundation
- `LICENSE-MIT`: Copyright (c) 2016 Artyom Pavlov
- `LICENSE-MIT`: Copyright (c) 2016-2026 The RustCrypto Project Developers

### sha2 0.11.0

- `LICENSE-MIT`: Copyright (c) 2006-2009 Graydon Hoare
- `LICENSE-MIT`: Copyright (c) 2009-2013 Mozilla Foundation
- `LICENSE-MIT`: Copyright (c) 2016 Artyom Pavlov
- `LICENSE-MIT`: Copyright (c) 2016-2026 The RustCrypto Project Developers

### sha3 0.11.0

- `LICENSE-MIT`: Copyright (c) 2006-2009 Graydon Hoare
- `LICENSE-MIT`: Copyright (c) 2009-2013 Mozilla Foundation
- `LICENSE-MIT`: Copyright (c) 2014 Sébastien Martini
- `LICENSE-MIT`: Copyright (c) 2016-2023 Artyom Pavlov, Marek Kotewicz
- `LICENSE-MIT`: Copyright (c) 2020-2026 The RustCrypto Project Developers

### sha3 0.12.0

- `LICENSE-MIT`: Copyright (c) 2006-2009 Graydon Hoare
- `LICENSE-MIT`: Copyright (c) 2009-2013 Mozilla Foundation
- `LICENSE-MIT`: Copyright (c) 2014 Sébastien Martini
- `LICENSE-MIT`: Copyright (c) 2016-2023 Artyom Pavlov, Marek Kotewicz
- `LICENSE-MIT`: Copyright (c) 2020-2026 The RustCrypto Project Developers

### signal-hook-registry 1.4.8

- `LICENSE-MIT`: Copyright (c) 2017 tokio-jsonrpc developers

### signature 3.0.0

- `LICENSE-MIT`: Copyright (c) 2018-2026 RustCrypto Developers

### slab 0.4.12

- `LICENSE`: Copyright (c) 2019 Carl Lerche

### smallvec 1.15.2

- `LICENSE-MIT`: Copyright (c) 2018 The Servo Project Developers

### socket2 0.6.5

- `LICENSE-MIT`: Copyright (c) 2014 Alex Crichton

### spki 0.8.0

- `LICENSE-MIT`: Copyright (c) 2021-2026 The RustCrypto Project Developers

### sponge-cursor 0.1.0

- `LICENSE-MIT`: Copyright (c) 2026 The RustCrypto Project Developers

### ssh-cipher 0.3.0

- `LICENSE-MIT`: Copyright (c) 2023-2026 The RustCrypto Project Developers

### ssh-encoding 0.3.0

- `LICENSE-MIT`: Copyright (c) 2021-2026 The RustCrypto Project Developers

### ssh-key 0.7.0-rc.11

- `LICENSE-MIT`: Copyright (c) 2021-2026 The RustCrypto Project Developers

### subtle 2.6.1

- `LICENSE`: Copyright (c) 2016-2017 Isis Agora Lovecruft, Henry de Valence. All rights reserved.
- `LICENSE`: Copyright (c) 2016-2024 Isis Agora Lovecruft. All rights reserved.

### syn 2.0.119


### syn 3.0.3


### tempfile 3.27.0

- `LICENSE-MIT`: Copyright (c) 2015 Steven Allen

### thiserror 2.0.19


### thiserror-impl 2.0.19


### tokio 1.53.1

- `LICENSE`: Copyright (c) Tokio Contributors

### tokio-macros 2.7.2

- `LICENSE`: Copyright (c) 2019 Yoshua Wuyts
- `LICENSE`: Copyright (c) Tokio Contributors

### tokio-util 0.7.19

- `LICENSE`: Copyright (c) Tokio Contributors

### typenum 1.20.1

- `LICENSE-APACHE`: Copyright 2014 Paho Lurie-Gregg
- `LICENSE-MIT`: Copyright (c) 2014 Paho Lurie-Gregg

### unicode-ident 1.0.24


### universal-hash 0.6.1

- `LICENSE-MIT`: Copyright (c) 2019-2025 RustCrypto Developers

### wnaf 0.14.0

- `LICENSE-MIT`: Copyright (c) 2018-2025 `group` crate developers
- `LICENSE-MIT`: Copyright (c) 2026 RustCrypto Developers

### zeroize 1.9.0

- `LICENSE-MIT`: Copyright (c) 2018-2026 The RustCrypto Project Developers

## Retained license, attribution, and notice texts

### Apache License 2.0 — vendored Russh 0.62.5

Source input: `$REPO_ROOT/crates/vendor/russh-0.62.5/LICENSE.txt` (SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`).

```text

                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

### MIT License — aead 0.6.1

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/aead-0.6.1/LICENSE-MIT` (SHA-256 `33b32a251d445c5c03a634e64c53314c55540fc367fabdd45d9b6c8f260c028c`).

```text
Copyright (c) 2019-2026 The RustCrypto Project Developers
Copyright (c) 2019 MobileCoin, LLC

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```

### BSD 3-Clause License — curve25519-dalek 5.0.0

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/curve25519-dalek-5.0.0/LICENSE` (SHA-256 `403c53069750101aeb9df7e15f127056ceaf7e4e92d0b919a1f4c084afd5f1d4`).

```text
Copyright (c) 2016-2021 isis agora lovecruft. All rights reserved.
Copyright (c) 2016-2021 Henry de Valence. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### ISC License — untrusted 0.9.0

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/untrusted-0.9.0/LICENSE.txt` (SHA-256 `7abd9b6960dcf7d4d0a48606a5b71bfe37d472db68d70637f3a58a56785f1621`).

```text
// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

### Unlicense — byteorder 1.5.0

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/byteorder-1.5.0/UNLICENSE` (SHA-256 `7e12e5df4bae12cb21581ba157ced20e1986a0508dd10d0e8a4ab9a4cf94e85c`).

```text
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>
```

### Zlib License — foldhash 0.2.0

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/foldhash-0.2.0/LICENSE` (SHA-256 `b1181a40b2a7b25cf66fd01481713bc1005df082c53ef73e851e55071b102744`).

```text
Copyright (c) 2024 Orson Peters

This software is provided 'as-is', without any express or implied warranty. In
no event will the authors be held liable for any damages arising from the use of
this software.

Permission is granted to anyone to use this software for any purpose, including
commercial applications, and to alter it and redistribute it freely, subject to
the following restrictions:

1. The origin of this software must not be misrepresented; you must not claim
    that you wrote the original software. If you use this software in a product,
    an acknowledgment in the product documentation would be appreciated but is
    not required.

2. Altered source versions must be plainly marked as such, and must not be
    misrepresented as being the original software.

3. This notice may not be removed or altered from any source distribution.
```

### Unicode License V3 — unicode-ident 1.0.24

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/unicode-ident-1.0.24/LICENSE-UNICODE` (SHA-256 `f7db81051789b729fea528a63ec4c938fdcb93d9d61d97dc8cc2e9df6d47f2a1`).

```text
UNICODE LICENSE V3

COPYRIGHT AND PERMISSION NOTICE

Copyright © 1991-2023 Unicode, Inc.

NOTICE TO USER: Carefully read the following legal agreement. BY
DOWNLOADING, INSTALLING, COPYING OR OTHERWISE USING DATA FILES, AND/OR
SOFTWARE, YOU UNEQUIVOCALLY ACCEPT, AND AGREE TO BE BOUND BY, ALL OF THE
TERMS AND CONDITIONS OF THIS AGREEMENT. IF YOU DO NOT AGREE, DO NOT
DOWNLOAD, INSTALL, COPY, DISTRIBUTE OR USE THE DATA FILES OR SOFTWARE.

Permission is hereby granted, free of charge, to any person obtaining a
copy of data files and any associated documentation (the "Data Files") or
software and any associated documentation (the "Software") to deal in the
Data Files or Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, and/or sell
copies of the Data Files or Software, and to permit persons to whom the
Data Files or Software are furnished to do so, provided that either (a)
this copyright and permission notice appear with all copies of the Data
Files or Software, or (b) this copyright and permission notice appear in
associated Documentation.

THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF
THIRD PARTY RIGHTS.

IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS INCLUDED IN THIS NOTICE
BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES,
OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE DATA
FILES OR SOFTWARE.

Except as contained in this notice, the name of a copyright holder shall
not be used in advertising or otherwise to promote the sale, use or other
dealings in these Data Files or Software without prior written
authorization of the copyright holder.
```

### Apache License 2.0 with LLVM Exception — linux-raw-sys 0.12.1

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/linux-raw-sys-0.12.1/LICENSE-Apache-2.0_WITH_LLVM-exception` (SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`).

```text

                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.


--- LLVM Exceptions to the Apache 2.0 License ----

As an exception, if, as a result of your compiling your source code, portions
of this Software are embedded into an Object form of such source code, you
may redistribute such embedded portions in such Object form without complying
with the conditions of Sections 4(a), 4(b) and 4(d) of the License.

In addition, if you combine or link compiled forms of this Software with
software that is licensed under the GPLv2 ("Combined Software") and if a
court of competent jurisdiction determines that the patent provision (Section
3), the indemnity provision (Section 9) or other Section of the License
conflicts with the conditions of the GPLv2, you may retroactively and
prospectively choose to deem waived or otherwise exclude such Section(s) of
the License, but only in their entirety and only with respect to the Combined
Software.

```

### ring 0.17.14 license map

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/ring-0.17.14/LICENSE` (SHA-256 `b3d734001a94efff3579978d953391aa7115f877657d25eb54037a43875d078a`).

```text
*ring* uses an "ISC" license, like BoringSSL used to use, for new code
files. See LICENSE-other-bits for the text of that license.

See LICENSE-BoringSSL for code that was sourced from BoringSSL under the
Apache 2.0 license. Some code that was sourced from BoringSSL under the ISC
license. In each case, the license info is at the top of the file.

See src/polyfill/once_cell/LICENSE-APACHE and src/polyfill/once_cell/LICENSE-MIT
for the license to code that was sourced from the once_cell project.
```

### ring 0.17.14 BoringSSL terms

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/ring-0.17.14/LICENSE-BoringSSL` (SHA-256 `005fc765ddc5115da796cca915baa9557abae13ff35e0a47c47affc56f6c414d`).

```text

                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.


Licenses for support code
-------------------------

Parts of the TLS test suite are under the Go license. This code is not included
in BoringSSL (i.e. libcrypto and libssl) when compiled, however, so
distributing code linked against BoringSSL does not trigger this license:

Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


BoringSSL uses the Chromium test infrastructure to run a continuous build,
trybots etc. The scripts which manage this, and the script for generating build
metadata, are under the Chromium license. Distributing code linked against
BoringSSL does not trigger this license.

Copyright 2015 The Chromium Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### ring 0.17.14 other-bits ISC terms

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/ring-0.17.14/LICENSE-other-bits` (SHA-256 `f025ccfb7dfb6bdfedc75ca0f67acc69e6fb4998143d834f7c2f38a29989680f`).

```text
Copyright 2015-2025 Brian Smith.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

### ring 0.17.14 fiat terms

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/ring-0.17.14/third_party/fiat/LICENSE` (SHA-256 `9eacbcb81be660840c714a560a9d65ba07913db98dd4baf969f78dd499fdd60f`).

```text
The Apache License, Version 2.0 (Apache-2.0)

Copyright 2015-2020 the fiat-crypto authors (see the AUTHORS file)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

### curve25519-dalek 5.0.0 acknowledgements

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/curve25519-dalek-5.0.0/ACKNOWLEDGEMENTS.md` (SHA-256 `32e1c1a46afc28f996f7c3d83337f6b15669f56bbd4378f6a8942026563214df`).

````text
# Go ed25519

Portions of curve25519-dalek were originally derived from Adam Langley's
Go ed25519 implementation, found at <https://github.com/agl/ed25519/>,
under the following licence:

```
Copyright (c) 2012 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

# Lizard

The `src/lizard` directory was copied from [Signal's curve25519-dalek repo]( https://github.com/signalapp/curve25519-dalek/tree/7c6d34756355a3566a704da84dce7b1c039a6572). Its license is copied below

```
MIT License

Copyright (c) 2019 Bas Westerbaan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
````

### encoding_rs 0.8.35 copyright notice

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/encoding_rs-0.8.35/COPYRIGHT` (SHA-256 `11789f45bb180841cd362a5eee6789c68ddb573a11105e30768c308a6add0190`).

```text
encoding_rs is copyright Mozilla Foundation.

Licensed under the Apache License, Version 2.0
<LICENSE-APACHE or
https://www.apache.org/licenses/LICENSE-2.0> or the MIT
license <LICENSE-MIT or https://opensource.org/licenses/MIT>,
at your option. All files in the project carrying such
notice may not be copied, modified, or distributed except
according to those terms.

This crate includes data derived from the data files supplied
with the WHATWG Encoding Standard, which, when incorporated into
source code, are licensed under the BSD 3-Clause License
<LICENSE-WHATWG>.

Test code within encoding_rs is dedicated to the Public Domain when so
designated (see the individual files for PD/CC0-dedicated sections).
```

### encoding_rs 0.8.35 WHATWG terms

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/encoding_rs-0.8.35/LICENSE-WHATWG` (SHA-256 `838118388fe5c2e7f1dbbaeed13e1c7f3ebf88be91319c7c1d77c18e987d1a50`).

```text
Copyright © WHATWG (Apple, Google, Mozilla, Microsoft).

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### md5 0.8.1 license

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/md5-0.8.1/LICENSE.md` (SHA-256 `2096783a9b939ae2a3a4789d9696740cec1a72ac04ccf8a7972d436fd0e7b240`).

````text
# License

The project is dual licensed under the terms of the Apache License, Version 2.0,
and the MIT License. You may obtain copies of the two licenses at

* https://www.apache.org/licenses/LICENSE-2.0 and
* https://opensource.org/licenses/MIT, respectively.

The following two notices apply to every file of the project.

## The Apache License

```
Copyright 2015–2026 The md5 Developers

Licensed under the Apache License, Version 2.0 (the “License”); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an “AS IS” BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
```

## The MIT License

```
Copyright 2015–2026 The md5 Developers

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the “Software”), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```
````

### group 0.14.0 copyright notice

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/group-0.14.0/COPYRIGHT` (SHA-256 `7429802d3e67e3308471b91fbea341e484c4e0a23d0fb230a8636c38184cec79`).

```text
Copyrights in the "group" library are retained by their contributors. No
copyright assignment is required to contribute to the "group" library.

The "group" library is licensed under either of

 * Apache License, Version 2.0, (see ./LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license (see ./LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
```

### linux-raw-sys 0.12.1 copyright notice

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/linux-raw-sys-0.12.1/COPYRIGHT` (SHA-256 `3290ae0fbc9ddb77d2239121d710f0bb9d31b3b4744e6d97fe01e652b4c1870b`).

```text
Short version for non-lawyers:

`linux-raw-sys` is triple-licensed under Apache 2.0 with the LLVM Exception,
Apache 2.0, and MIT terms.


Longer version:

Copyrights in the `linux-raw-sys` project are retained by their contributors.
No copyright assignment is required to contribute to the `linux-raw-sys`
project.

Some files include code derived from Rust's `libstd`; see the comments in
the code for details.

Except as otherwise noted (below and/or in individual files), `linux-raw-sys`
is licensed under:

 - the Apache License, Version 2.0, with the LLVM Exception
   <LICENSE-Apache-2.0_WITH_LLVM-exception> or
   <http://llvm.org/foundation/relicensing/LICENSE.txt>
 - the Apache License, Version 2.0
   <LICENSE-APACHE> or
   <http://www.apache.org/licenses/LICENSE-2.0>,
 - or the MIT license
   <LICENSE-MIT> or
   <http://opensource.org/licenses/MIT>,

at your option.
```
### rand 0.10.2 copyright notice

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/rand-0.10.2/COPYRIGHT` (SHA-256 `90eb64f0279b0d9432accfa6023ff803bc4965212383697eee27a0f426d5f8d5`).

```text
Copyrights in the Rand project are retained by their contributors. No
copyright assignment is required to contribute to the Rand project.

For full authorship information, see the version control history.

Except as otherwise noted (below and/or in individual files), Rand is
licensed under the Apache License, Version 2.0 <LICENSE-APACHE> or
<http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
<LICENSE-MIT> or <http://opensource.org/licenses/MIT>, at your option.

The Rand project includes code from the Rust project
published under these same licenses.
```

### rand_core 0.10.1 copyright notice

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/rand_core-0.10.1/COPYRIGHT` (SHA-256 `92b81db30f7ab6d693e0af5661a40d273ca1947e891123ed823924192c10cbc7`).

```text
Copyrights in the Rand project are retained by their contributors. No
copyright assignment is required to contribute to the Rand project.

For full authorship information, see the version control history.

Except as otherwise noted (below and/or in individual files), Rand is
licensed under the Apache License, Version 2.0 <LICENSE-APACHE> or
<http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
<LICENSE-MIT> or <http://opensource.org/licenses/MIT>, at your option.
```

### rustix 1.1.4 copyright notice

Source input: `$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/rustix-1.1.4/COPYRIGHT` (SHA-256 `377c2e7c53250cc5905c0b0532d35973392af16ffb9596a41d99d202cf3617c9`).

```text
Short version for non-lawyers:

`rustix` is triple-licensed under Apache 2.0 with the LLVM Exception,
Apache 2.0, and MIT terms.


Longer version:

Copyrights in the `rustix` project are retained by their contributors.
No copyright assignment is required to contribute to the `rustix`
project.

Some files include code derived from Rust's `libstd`; see the comments in
the code for details.

Except as otherwise noted (below and/or in individual files), `rustix`
is licensed under:

 - the Apache License, Version 2.0, with the LLVM Exception
   <LICENSE-Apache-2.0_WITH_LLVM-exception> or
   <http://llvm.org/foundation/relicensing/LICENSE.txt>
 - the Apache License, Version 2.0
   <LICENSE-APACHE> or
   <http://www.apache.org/licenses/LICENSE-2.0>,
 - or the MIT license
   <LICENSE-MIT> or
   <http://opensource.org/licenses/MIT>,

at your option.
```
