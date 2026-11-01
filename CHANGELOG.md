# Changelog

## [0.83.0](https://github.com/villebase/sopuli-dba/compare/v0.82.0...v0.83.0) (2026-11-01)


### Features

* **config:** declare a MySQL target ([#1221](https://github.com/villebase/sopuli-dba/issues/1221)) ([#1226](https://github.com/villebase/sopuli-dba/issues/1226)) ([710662b](https://github.com/villebase/sopuli-dba/commit/710662bf199e5d15b97e7ef66feca17caef62322))
* deliver a personal account's password as a 1Password share link ([#446](https://github.com/villebase/sopuli-dba/issues/446)) ([#1192](https://github.com/villebase/sopuli-dba/issues/1192)) ([a40c581](https://github.com/villebase/sopuli-dba/commit/a40c5812dbc686c7dccccfa91e7389fa2047f2a4))
* **driver:** build the MySQL connection arguments and client line ([#1221](https://github.com/villebase/sopuli-dba/issues/1221)) ([#1230](https://github.com/villebase/sopuli-dba/issues/1230)) ([719102f](https://github.com/villebase/sopuli-dba/commit/719102fd1dc28c7c3229f6e86b0359b7bb0ecc82))
* **driver:** map a MySQL error number to a category and a hint ([#1221](https://github.com/villebase/sopuli-dba/issues/1221)) ([#1231](https://github.com/villebase/sopuli-dba/issues/1231)) ([58dbc09](https://github.com/villebase/sopuli-dba/commit/58dbc098cb9eb3da1b3a0f86db30dbd2f224e7bb))
* measure a client-side MySQL hash and dual passwords ([#1202](https://github.com/villebase/sopuli-dba/issues/1202)) ([#1216](https://github.com/villebase/sopuli-dba/issues/1216)) ([e854067](https://github.com/villebase/sopuli-dba/commit/e854067dd48a28d1a2eb7cdfd7ad7925d005faf0))
* measure MySQL lock, expiry, account identity and tool grants ([#1202](https://github.com/villebase/sopuli-dba/issues/1202)) ([#1217](https://github.com/villebase/sopuli-dba/issues/1217)) ([7e2e855](https://github.com/villebase/sopuli-dba/commit/7e2e855e83f6d8588a1bf0c5c6bfc12ac0d23ed6))
* measure what MySQL keeps of a password change ([#1202](https://github.com/villebase/sopuli-dba/issues/1202)) ([#1215](https://github.com/villebase/sopuli-dba/issues/1215)) ([fd6b30d](https://github.com/villebase/sopuli-dba/commit/fd6b30dc6b48db4b7f607005dc6bd54a876618c7))
* name the guardrails that refuse an admitted account in account list ([#1207](https://github.com/villebase/sopuli-dba/issues/1207)) ([#1212](https://github.com/villebase/sopuli-dba/issues/1212)) ([ad385c7](https://github.com/villebase/sopuli-dba/commit/ad385c750b5733d72f9277ed8db722a91297c766))
* read onepassword_share's keys and check the 1Password account at plan time ([#446](https://github.com/villebase/sopuli-dba/issues/446)) ([#1189](https://github.com/villebase/sopuli-dba/issues/1189)) ([8f4f813](https://github.com/villebase/sopuli-dba/commit/8f4f813f6e475144db2e2ee337413f5bf640e6b0))
* reset a personal account's password on PostgreSQL ([#1201](https://github.com/villebase/sopuli-dba/issues/1201)) ([#1209](https://github.com/villebase/sopuli-dba/issues/1209)) ([9004b99](https://github.com/villebase/sopuli-dba/commit/9004b990ea98c87af9ca7458057327faac2fe029))
* run account list on PostgreSQL with a role: predicate ([#1201](https://github.com/villebase/sopuli-dba/issues/1201)) ([#1206](https://github.com/villebase/sopuli-dba/issues/1206)) ([55eb10f](https://github.com/villebase/sopuli-dba/commit/55eb10f7c7fdaa9ad7708059fa1a4b9a21a5fd16))
* suspend a personal account on PostgreSQL ([#1201](https://github.com/villebase/sopuli-dba/issues/1201)) ([#1211](https://github.com/villebase/sopuli-dba/issues/1211)) ([213a1f4](https://github.com/villebase/sopuli-dba/commit/213a1f41592a9484f47f7f33411dd5e2a86ffed8))


### Bug Fixes

* compare account, role and profile names by upper() everywhere ([#1208](https://github.com/villebase/sopuli-dba/issues/1208)) ([#1210](https://github.com/villebase/sopuli-dba/issues/1210)) ([ee4029c](https://github.com/villebase/sopuli-dba/commit/ee4029ca0b3323dddb9340b309d9ad7ad69a0274))
* refuse at plan time a lock name held by a secret scheduled for deletion ([#1188](https://github.com/villebase/sopuli-dba/issues/1188)) ([#1190](https://github.com/villebase/sopuli-dba/issues/1190)) ([820bbbe](https://github.com/villebase/sopuli-dba/commit/820bbbe866fc9a9ce633a1d8905fb7ff722b9fca))

## [0.82.0](https://github.com/villebase/sopuli-dba/compare/v0.81.0...v0.82.0) (2026-10-30)


### Features

* a store adapter for native staging under the UC-1 verbs ([#1158](https://github.com/villebase/sopuli-dba/issues/1158)) ([#1161](https://github.com/villebase/sopuli-dba/issues/1161)) ([63331d3](https://github.com/villebase/sopuli-dba/commit/63331d329305958f3f51a769f66c8138ceab321e))
* add native staging to the store protocol and the in-memory store ([#1131](https://github.com/villebase/sopuli-dba/issues/1131)) ([#1143](https://github.com/villebase/sopuli-dba/issues/1143)) ([26a5b66](https://github.com/villebase/sopuli-dba/commit/26a5b6689d676e2b6d864536791d1850732d5a96))
* authenticate to an OCI store with a session token or a principal ([#1146](https://github.com/villebase/sopuli-dba/issues/1146)) ([#1148](https://github.com/villebase/sopuli-dba/issues/1148)) ([226e0f7](https://github.com/villebase/sopuli-dba/commit/226e0f7a9c7ab9d7431fc9d1a20179b22a86a863))
* check an OCI store's version limit and deleting names at plan time ([#1159](https://github.com/villebase/sopuli-dba/issues/1159)) ([#1170](https://github.com/villebase/sopuli-dba/issues/1170)) ([763f371](https://github.com/villebase/sopuli-dba/commit/763f3711666ac16375101674eb90e9a56497e2b9))
* connect to an OCI store and check its health ([#1132](https://github.com/villebase/sopuli-dba/issues/1132)) ([#1147](https://github.com/villebase/sopuli-dba/issues/1147)) ([dfc2906](https://github.com/villebase/sopuli-dba/commit/dfc2906696e8e7017e8ae413dee663ea003dce27))
* forecast a guardrail refusal on an account's only target in a dry run ([#1116](https://github.com/villebase/sopuli-dba/issues/1116)) ([#1184](https://github.com/villebase/sopuli-dba/issues/1184)) ([273cc7c](https://github.com/villebase/sopuli-dba/commit/273cc7c035c78468c2cd06d4357b00a41d0fc42c))
* keep lock records in OCI secret metadata ([#1152](https://github.com/villebase/sopuli-dba/issues/1152)) ([#1156](https://github.com/villebase/sopuli-dba/issues/1156)) ([87a9641](https://github.com/villebase/sopuli-dba/commit/87a964192b92ee53100d792cdd2b3191f2254936))
* list an OCI store's OCIDs in config show; check its admin ref names ([#1145](https://github.com/villebase/sopuli-dba/issues/1145)) ([#1150](https://github.com/villebase/sopuli-dba/issues/1150)) ([b4ae186](https://github.com/villebase/sopuli-dba/commit/b4ae1860167bb9eb36e7a423c164bf8ac85fa29e))
* **postgres:** refuse a role supautils reserves, at plan time ([#1111](https://github.com/villebase/sopuli-dba/issues/1111)) ([#1113](https://github.com/villebase/sopuli-dba/issues/1113)) ([a933e49](https://github.com/villebase/sopuli-dba/commit/a933e496d6d5075bf5101f361c6b8e051bcbdf61))
* read an OCI store's vault, compartment and key ([#1130](https://github.com/villebase/sopuli-dba/issues/1130)) ([#1139](https://github.com/villebase/sopuli-dba/issues/1139)) ([2234fe2](https://github.com/villebase/sopuli-dba/commit/2234fe2669cae8894f67e63c11d99e77186ce1ee))
* read and list an OCI store ([#1144](https://github.com/villebase/sopuli-dba/issues/1144)) ([#1149](https://github.com/villebase/sopuli-dba/issues/1149)) ([9e2fbd6](https://github.com/villebase/sopuli-dba/commit/9e2fbd64df31d5478374e8e580c0b204eb23077c))
* refuse a ref on an OCI store that is not an OCI secret name ([#1137](https://github.com/villebase/sopuli-dba/issues/1137)) ([#1140](https://github.com/villebase/sopuli-dba/issues/1140)) ([fba6d4c](https://github.com/villebase/sopuli-dba/commit/fba6d4c4e32d73973f2b522412a0954d8d711df5))
* refuse personal accounts on an OCI store ([#1138](https://github.com/villebase/sopuli-dba/issues/1138)) ([#1142](https://github.com/villebase/sopuli-dba/issues/1142)) ([e4feefe](https://github.com/villebase/sopuli-dba/commit/e4feefeb2e045a78fd1ca9f558b2c5f5d35af50c))
* **reset:** allow the seen reset on a rollover profile and close the window ([#541](https://github.com/villebase/sopuli-dba/issues/541)) ([#1127](https://github.com/villebase/sopuli-dba/issues/1127)) ([d017163](https://github.com/villebase/sopuli-dba/commit/d017163ca3e7430c81fdabc31c25fbf2a953d388))
* stage, promote, and make room at the version limit on an OCI store ([#1153](https://github.com/villebase/sopuli-dba/issues/1153)) ([#1157](https://github.com/villebase/sopuli-dba/issues/1157)) ([18783ba](https://github.com/villebase/sopuli-dba/commit/18783ba4496566abc7b3a7e2721fd9c6feb9a423))
* use native staging for a one-account secret on an OCI store ([#1134](https://github.com/villebase/sopuli-dba/issues/1134)) ([#1162](https://github.com/villebase/sopuli-dba/issues/1162)) ([f537227](https://github.com/villebase/sopuli-dba/commit/f537227097b455c9b0d1ee743d3d8088a5454018))
* write and create secrets on an OCI store under compare-and-set ([#1133](https://github.com/villebase/sopuli-dba/issues/1133)) ([#1155](https://github.com/villebase/sopuli-dba/issues/1155)) ([242e153](https://github.com/villebase/sopuli-dba/commit/242e15373ee9047914a473af95cafaf5b2dcc652))


### Bug Fixes

* check stage collisions over the whole estate when the run supplies the store ([#1141](https://github.com/villebase/sopuli-dba/issues/1141)) ([#1160](https://github.com/villebase/sopuli-dba/issues/1160)) ([c7e2201](https://github.com/villebase/sopuli-dba/commit/c7e22019d34d8effe3416f5ea4b3b518550f6bbe))
* exit 9 from doctor when a target it reached is refused for its setup ([#1062](https://github.com/villebase/sopuli-dba/issues/1062)) ([#1172](https://github.com/villebase/sopuli-dba/issues/1172)) ([9bc12ea](https://github.com/villebase/sopuli-dba/commit/9bc12ea06ad080a05e39c0946ea58dc4d2b57c7b))
* import psycopg where the PostgreSQL password module uses it ([#1168](https://github.com/villebase/sopuli-dba/issues/1168)) ([#1177](https://github.com/villebase/sopuli-dba/issues/1177)) ([5e201d9](https://github.com/villebase/sopuli-dba/commit/5e201d9f52bae59332e9f757d795b8a5c16db174))
* leave a role check 6 or 8 refuses out of rotate's privilege survey ([#1117](https://github.com/villebase/sopuli-dba/issues/1117)) ([#1175](https://github.com/villebase/sopuli-dba/issues/1175)) ([4301c94](https://github.com/villebase/sopuli-dba/commit/4301c94e7b093553c1dc1c1c4982fd3359f30acf))
* name an OCI orphan by its secret name, and print its OCI delete command ([#1186](https://github.com/villebase/sopuli-dba/issues/1186)) ([#1187](https://github.com/villebase/sopuli-dba/issues/1187)) ([50cc443](https://github.com/villebase/sopuli-dba/commit/50cc4434f65d842e32af62344bf6dcb50672e890))
* refuse an application's account that a predicate admits in account verbs ([#1056](https://github.com/villebase/sopuli-dba/issues/1056)) ([#1183](https://github.com/villebase/sopuli-dba/issues/1183)) ([2f6c150](https://github.com/villebase/sopuli-dba/commit/2f6c1507c88e2a4c33137923d6057e01009cbbe0))
* refuse hash mode for a common account outside CDB$ROOT, naming the container ([#1126](https://github.com/villebase/sopuli-dba/issues/1126)) ([#1163](https://github.com/villebase/sopuli-dba/issues/1163)) ([ebef966](https://github.com/villebase/sopuli-dba/commit/ebef9663c8bb665663539eeab11e499482f2a118))
* report no lockout guard for a common account outside the root ([#1122](https://github.com/villebase/sopuli-dba/issues/1122)) ([#1125](https://github.com/villebase/sopuli-dba/issues/1125)) ([1cbd3b1](https://github.com/villebase/sopuli-dba/commit/1cbd3b114fdc1916260dfba720b0bab16f8837b8))
* skip a shared password another target refuses on every target in apply ([#1180](https://github.com/villebase/sopuli-dba/issues/1180)) ([#1181](https://github.com/villebase/sopuli-dba/issues/1181)) ([19591c5](https://github.com/villebase/sopuli-dba/commit/19591c5ba86109ab46ee0e6051e1a5d4b2df3903))
* skip an account check 6 or 8 refuses in creds generate ([#1174](https://github.com/villebase/sopuli-dba/issues/1174)) ([#1179](https://github.com/villebase/sopuli-dba/issues/1179)) ([cb2326c](https://github.com/villebase/sopuli-dba/commit/cb2326ca3b37c75d9d8b2c6eaaa78d3f3cd392ee))
* take a write's version number from the OCI store, not a read-back ([#1164](https://github.com/villebase/sopuli-dba/issues/1164)) ([#1178](https://github.com/villebase/sopuli-dba/issues/1178)) ([3a1c4ae](https://github.com/villebase/sopuli-dba/commit/3a1c4ae4624d420cbad3f4c1e7642569b8d2db51))

## [0.81.0](https://github.com/villebase/sopuli-dba/compare/v0.80.0...v0.81.0) (2026-10-27)


### Features

* **apply:** refuse an account attribute a target cannot enforce, at plan time ([#1072](https://github.com/villebase/sopuli-dba/issues/1072)) ([#1074](https://github.com/villebase/sopuli-dba/issues/1074)) ([0ac3603](https://github.com/villebase/sopuli-dba/commit/0ac36039f2b72acebd67c7a039df197e052575c6))
* **check:** run creds check on a PostgreSQL target ([#1067](https://github.com/villebase/sopuli-dba/issues/1067)) ([#1071](https://github.com/villebase/sopuli-dba/issues/1071)) ([4eb9332](https://github.com/villebase/sopuli-dba/commit/4eb9332e02181e721efcd0c3333aa6be41bec131))
* **config:** declare a PostgreSQL target ([#1038](https://github.com/villebase/sopuli-dba/issues/1038)) ([#1039](https://github.com/villebase/sopuli-dba/issues/1039)) ([ce78e71](https://github.com/villebase/sopuli-dba/commit/ce78e716c229816dff04336c9b276913d3e79107))
* **config:** read the one_time_link delivery block ([#445](https://github.com/villebase/sopuli-dba/issues/445)) ([#1109](https://github.com/villebase/sopuli-dba/issues/1109)) ([1215616](https://github.com/villebase/sopuli-dba/commit/1215616a7394987498a2d5cbb2c19d9cdde8de69))
* **config:** read the vault_path delivery block ([#447](https://github.com/villebase/sopuli-dba/issues/447)) ([#1102](https://github.com/villebase/sopuli-dba/issues/1102)) ([b4b702b](https://github.com/villebase/sopuli-dba/commit/b4b702b0d9068de29912772f1d1e780de47bb5e8))
* **delivery:** add the Yopass backend for one_time_link ([#445](https://github.com/villebase/sopuli-dba/issues/445)) ([#1110](https://github.com/villebase/sopuli-dba/issues/1110)) ([f010435](https://github.com/villebase/sopuli-dba/commit/f010435a02bcc30526061e64885801dcdac49f59))
* **delivery:** deliver a personal password by one_time_link ([#445](https://github.com/villebase/sopuli-dba/issues/445)) ([#1112](https://github.com/villebase/sopuli-dba/issues/1112)) ([87b3296](https://github.com/villebase/sopuli-dba/commit/87b3296fee8094d9a0419510cfaaee3ca3f9a333))
* **delivery:** deliver a personal password by vault_path ([#447](https://github.com/villebase/sopuli-dba/issues/447)) ([#1103](https://github.com/villebase/sopuli-dba/issues/1103)) ([ff0876e](https://github.com/villebase/sopuli-dba/commit/ff0876eb5e6242c081556010dcc32f4e605d3a71))
* **driver:** audit the PostgreSQL tool account's privileges ([#1047](https://github.com/villebase/sopuli-dba/issues/1047)) ([#1049](https://github.com/villebase/sopuli-dba/issues/1049)) ([575fab5](https://github.com/villebase/sopuli-dba/commit/575fab5b1a2cb878c688ac41dffafe491a605499))
* **driver:** build the PostgreSQL connection parameters and client lines ([#1040](https://github.com/villebase/sopuli-dba/issues/1040)) ([#1041](https://github.com/villebase/sopuli-dba/issues/1041)) ([d533411](https://github.com/villebase/sopuli-dba/commit/d533411731ed13cd4f508e4658af24391dc4b719))
* **driver:** connect to a PostgreSQL cluster and report it in doctor ([#1040](https://github.com/villebase/sopuli-dba/issues/1040)) ([#1044](https://github.com/villebase/sopuli-dba/issues/1044)) ([18a0ceb](https://github.com/villebase/sopuli-dba/commit/18a0ceb9bfab1c0aed1dd2b51e545e6ac5827eed))
* **driver:** describe a PostgreSQL role for the guardrails ([#1059](https://github.com/villebase/sopuli-dba/issues/1059)) ([#1064](https://github.com/villebase/sopuli-dba/issues/1064)) ([d99d2fb](https://github.com/villebase/sopuli-dba/commit/d99d2fb5f61ef102d1280ac434a18e84af3da865))
* **driver:** map a PostgreSQL SQLSTATE, and recover it from a failed login's message ([#1040](https://github.com/villebase/sopuli-dba/issues/1040)) ([#1042](https://github.com/villebase/sopuli-dba/issues/1042)) ([d2aabfb](https://github.com/villebase/sopuli-dba/commit/d2aabfb6f4bd9c23f1f646491df6889cd168fa95))
* **driver:** refuse a PostgreSQL superuser and one cluster declared twice ([#1047](https://github.com/villebase/sopuli-dba/issues/1047)) ([#1050](https://github.com/villebase/sopuli-dba/issues/1050)) ([a8c3574](https://github.com/villebase/sopuli-dba/commit/a8c3574a75a739c583ec0a526e1cf3cf91a134ca))
* **driver:** report a PostgreSQL session's scope as a cluster, in run schema 1.62 ([#1040](https://github.com/villebase/sopuli-dba/issues/1040)) ([#1043](https://github.com/villebase/sopuli-dba/issues/1043)) ([2a99ac8](https://github.com/villebase/sopuli-dba/commit/2a99ac8654205ea66abc971f42e222590d872e90))
* **driver:** run creds apply on a PostgreSQL target ([#1060](https://github.com/villebase/sopuli-dba/issues/1060)) ([#1073](https://github.com/villebase/sopuli-dba/issues/1073)) ([1574324](https://github.com/villebase/sopuli-dba/commit/1574324430348f8dcefab92db223e2abb3f37963))
* **driver:** run creds rotate, generate and status on a PostgreSQL target ([#1072](https://github.com/villebase/sopuli-dba/issues/1072)) ([#1075](https://github.com/villebase/sopuli-dba/issues/1075)) ([50ea18d](https://github.com/villebase/sopuli-dba/commit/50ea18de385d22b058cdea116c9ce84a1bab7236))
* **driver:** set a PostgreSQL role's password with a client-side SCRAM verifier ([#1060](https://github.com/villebase/sopuli-dba/issues/1060)) ([#1070](https://github.com/villebase/sopuli-dba/issues/1070)) ([3a78fe4](https://github.com/villebase/sopuli-dba/commit/3a78fe48ba8185e48f5f32b8bfb175a1bca7095b))
* **driver:** verify a PostgreSQL role's password by logging in as it ([#1067](https://github.com/villebase/sopuli-dba/issues/1067)) ([#1069](https://github.com/villebase/sopuli-dba/issues/1069)) ([4b96d3a](https://github.com/villebase/sopuli-dba/commit/4b96d3a8d6bfd1aa5041dacb5abfc50020330ed0))
* **guardrails:** refuse a superuser and the tool's own account ([#1059](https://github.com/villebase/sopuli-dba/issues/1059)) ([#1063](https://github.com/villebase/sopuli-dba/issues/1063)) ([55a7c27](https://github.com/villebase/sopuli-dba/commit/55a7c27ce2fa3bb6c0c40309bb86ec1584545a62))
* **postgres:** hint that a target is a pooler when PgBouncer refuses a login ([#1105](https://github.com/villebase/sopuli-dba/issues/1105)) ([#1106](https://github.com/villebase/sopuli-dba/issues/1106)) ([e13a116](https://github.com/villebase/sopuli-dba/commit/e13a116d56c22e9914164f88b23577d4d209f591))
* **preflight:** refuse sslmode disable under require_encryption, and warn on an unverified PostgreSQL server ([#1058](https://github.com/villebase/sopuli-dba/issues/1058)) ([#1065](https://github.com/villebase/sopuli-dba/issues/1065)) ([7ed6b67](https://github.com/villebase/sopuli-dba/commit/7ed6b67207cb8a81b639ade040ccb3b4b3fb38c1))

## [0.80.0](https://github.com/villebase/sopuli-dba/compare/v0.79.0...v0.80.0) (2026-10-24)


### Features

* **audit:** keep a mixed-mode true only under a measured AUDIT_TRAIL ([#1013](https://github.com/villebase/sopuli-dba/issues/1013)) ([#1026](https://github.com/villebase/sopuli-dba/issues/1026)) ([71f36cb](https://github.com/villebase/sopuli-dba/commit/71f36cb7e703901e385fa39d47409ae0f415e5ef))
* **config:** refuse a user name or password in a vault address ([#891](https://github.com/villebase/sopuli-dba/issues/891)) ([#1029](https://github.com/villebase/sopuli-dba/issues/1029)) ([8bcc81d](https://github.com/villebase/sopuli-dba/commit/8bcc81d22645f8c394f2eae8c4b009631da70516))


### Bug Fixes

* **probes:** connect by EZConnect, not a TNS alias, in probes 11, 13 and 15 ([#1014](https://github.com/villebase/sopuli-dba/issues/1014)) ([#1024](https://github.com/villebase/sopuli-dba/issues/1024)) ([7d1f527](https://github.com/villebase/sopuli-dba/commit/7d1f527eec8e8afebc74c99e86994e3289c1bbd4))
* **vault:** percent-encode each path segment so a C## account's reset record is its own ([#884](https://github.com/villebase/sopuli-dba/issues/884)) ([#1028](https://github.com/villebase/sopuli-dba/issues/1028)) ([c35f123](https://github.com/villebase/sopuli-dba/commit/c35f1235414ad78ad58b37b3b4c971bb6ef8a128))

## [0.79.0](https://github.com/villebase/sopuli-dba/compare/v0.78.0...v0.79.0) (2026-10-23)


### Features

* **apply:** ask the guardrails on every target before the first change ([#872](https://github.com/villebase/sopuli-dba/issues/872)) ([#991](https://github.com/villebase/sopuli-dba/issues/991)) ([d765c18](https://github.com/villebase/sopuli-dba/commit/d765c18f6259e2fe8afae4eb774aa2f4c4320fe2))
* **apply:** say under --dry-run --preflight which credentials the guardrail pass would skip ([#988](https://github.com/villebase/sopuli-dba/issues/988)) ([#996](https://github.com/villebase/sopuli-dba/issues/996)) ([f7d3130](https://github.com/villebase/sopuli-dba/commit/f7d3130eaf55017eceaed4cd0018d73b27b7d73b))
* **audit:** answer unknown in mixed mode under AUDIT_TRAIL = NONE ([#1004](https://github.com/villebase/sopuli-dba/issues/1004)) ([#1010](https://github.com/villebase/sopuli-dba/issues/1010)) ([8dce53d](https://github.com/villebase/sopuli-dba/commit/8dce53d4e49230e342ba300e1349d10628fe11a1))
* **config:** ratchet a safety setting between --config files ([#855](https://github.com/villebase/sopuli-dba/issues/855)) ([#987](https://github.com/villebase/sopuli-dba/issues/987)) ([03689bd](https://github.com/villebase/sopuli-dba/commit/03689bdc68814158917ed96d78c96a7474d1495f))
* **config:** refuse a password over an unencrypted connection when required ([#857](https://github.com/villebase/sopuli-dba/issues/857)) ([#989](https://github.com/villebase/sopuli-dba/issues/989)) ([0f36e4d](https://github.com/villebase/sopuli-dba/commit/0f36e4ddf8c3395c1dd0c7a3b9ca2f44d8bf6a43))
* **config:** refuse a password policy below a length of 12 or 10 distinct characters ([#866](https://github.com/villebase/sopuli-dba/issues/866)) ([#984](https://github.com/villebase/sopuli-dba/issues/984)) ([f91489d](https://github.com/villebase/sopuli-dba/commit/f91489d1a7c16fbdf207179ecc48f19cb4750259))
* **config:** refuse a vault address or webhook URL that is not https, except on loopback ([#856](https://github.com/villebase/sopuli-dba/issues/856)) ([#986](https://github.com/villebase/sopuli-dba/issues/986)) ([feee9e3](https://github.com/villebase/sopuli-dba/commit/feee9e394bc892e8915abc470930fbaf059e20fa))
* **config:** refuse one database user bound to two places on one target ([#874](https://github.com/villebase/sopuli-dba/issues/874)) ([#985](https://github.com/villebase/sopuli-dba/issues/985)) ([5903994](https://github.com/villebase/sopuli-dba/commit/59039948b7a428ac4e2abcf83120ae1a4f6e7287))
* **rotate:** say under --dry-run which credentials the guardrail pass would skip ([#997](https://github.com/villebase/sopuli-dba/issues/997)) ([#1002](https://github.com/villebase/sopuli-dba/issues/1002)) ([4db6225](https://github.com/villebase/sopuli-dba/commit/4db622557f348b13902fc9ad9e8d9ef4c21b6502))
* **vault:** list vault records no binding declares ([#999](https://github.com/villebase/sopuli-dba/issues/999)) ([#1012](https://github.com/villebase/sopuli-dba/issues/1012)) ([70c9137](https://github.com/villebase/sopuli-dba/commit/70c91377181f386608c9b085eeb769c791318300))
* **vault:** survey only the paths under --prefix for vault orphans ([#1016](https://github.com/villebase/sopuli-dba/issues/1016)) ([#1022](https://github.com/villebase/sopuli-dba/issues/1022)) ([8042013](https://github.com/villebase/sopuli-dba/commit/80420133d4d5cf096ce6f2eee5620a78f8f22538))
* **vault:** survey only the stores named by --vault for vault orphans ([#1015](https://github.com/villebase/sopuli-dba/issues/1015)) ([#1017](https://github.com/villebase/sopuli-dba/issues/1017)) ([cf5133b](https://github.com/villebase/sopuli-dba/commit/cf5133b7385d09b75b676224582afed695640567))


### Bug Fixes

* **account:** report a guardrail check that could not run on the account verbs ([#971](https://github.com/villebase/sopuli-dba/issues/971)) ([#993](https://github.com/villebase/sopuli-dba/issues/993)) ([e0e390e](https://github.com/villebase/sopuli-dba/commit/e0e390ecccf4740f4a6b0c1fc1bf85860f4c3aa9))
* **audit:** keep only the server's first line, once, in the audited check's error details ([#1011](https://github.com/villebase/sopuli-dba/issues/1011)) ([#1021](https://github.com/villebase/sopuli-dba/issues/1021)) ([0252efe](https://github.com/villebase/sopuli-dba/commit/0252efed648ee27bf54d40adad228b4833938bad))
* **generate:** clear targets when --overwrite-current replaces a current ([#975](https://github.com/villebase/sopuli-dba/issues/975)) ([#995](https://github.com/villebase/sopuli-dba/issues/995)) ([e76d3bb](https://github.com/villebase/sopuli-dba/commit/e76d3bb3558a4b9cc2afc92eee8b5fea53f4187e))
* **orphans:** exit 1 when vault orphans could list no store ([#1018](https://github.com/villebase/sopuli-dba/issues/1018)) ([#1019](https://github.com/villebase/sopuli-dba/issues/1019)) ([7132544](https://github.com/villebase/sopuli-dba/commit/713254495dd193777c6deebaff8f7e50b7b06c07))
* **rotate:** read back only the accounts the promotion moved ([#1000](https://github.com/villebase/sopuli-dba/issues/1000)) ([#1003](https://github.com/villebase/sopuli-dba/issues/1003)) ([caf2645](https://github.com/villebase/sopuli-dba/commit/caf26459aff69565c5f5746a92c267b3ac28e38b))
* **rotate:** stage nothing the guardrails would skip ([#1009](https://github.com/villebase/sopuli-dba/issues/1009)) ([#1020](https://github.com/villebase/sopuli-dba/issues/1020)) ([0953dd9](https://github.com/villebase/sopuli-dba/commit/0953dd9dc0b6c603685a877332c36fb9a238d61e))

## [0.78.0](https://github.com/villebase/sopuli-dba/compare/v0.77.1...v0.78.0) (2026-10-22)


### Features

* **output:** say per plan unit what creds generate found in the vault ([#809](https://github.com/villebase/sopuli-dba/issues/809)) ([#974](https://github.com/villebase/sopuli-dba/issues/974)) ([8883a59](https://github.com/villebase/sopuli-dba/commit/8883a59ed53de5ba7829bd6ea1f01918369b767e))


### Bug Fixes

* **output:** report each rollover window rotate leaves open as its own W043 ([#825](https://github.com/villebase/sopuli-dba/issues/825)) ([#977](https://github.com/villebase/sopuli-dba/issues/977)) ([5e1ad9d](https://github.com/villebase/sopuli-dba/commit/5e1ad9d0ef25d6e21d21a673731c4cc89b6153a9))

## [0.77.1](https://github.com/villebase/sopuli-dba/compare/v0.77.0...v0.77.1) (2026-10-21)


### Bug Fixes

* **audit:** count a common logon policy for a common person ([#839](https://github.com/villebase/sopuli-dba/issues/839)) ([#925](https://github.com/villebase/sopuli-dba/issues/925)) ([d644d71](https://github.com/villebase/sopuli-dba/commit/d644d7148be9fe33446e4e75403b5d4e93cda266))
* **config:** refuse a / or # in a name a secret template uses ([#935](https://github.com/villebase/sopuli-dba/issues/935)) ([#939](https://github.com/villebase/sopuli-dba/issues/939)) ([1072ab0](https://github.com/villebase/sopuli-dba/commit/1072ab06b35d8091af4b855229832d82c9a09ffa))
* **config:** refuse a JSON pointer with an invalid ~ escape ([#928](https://github.com/villebase/sopuli-dba/issues/928)) ([#932](https://github.com/villebase/sopuli-dba/issues/932)) ([0001c91](https://github.com/villebase/sopuli-dba/commit/0001c91be9f7a2a7fcbe6166739fbb5f3d20d424))
* **config:** refuse a name that does a separator's job in a secret ref ([#940](https://github.com/villebase/sopuli-dba/issues/940)) ([#942](https://github.com/villebase/sopuli-dba/issues/942)) ([752c7d9](https://github.com/villebase/sopuli-dba/commit/752c7d95d58c83c5988d9d2ee07b087ba719226c))
* **oracle:** redact a password clause with no space after BY ([#944](https://github.com/villebase/sopuli-dba/issues/944)) ([#946](https://github.com/villebase/sopuli-dba/issues/946)) ([eebce00](https://github.com/villebase/sopuli-dba/commit/eebce00666276f21881bad22a43ad5322f254c25))
* **output:** carry the config's warnings in a failed run's document ([#918](https://github.com/villebase/sopuli-dba/issues/918)) ([#919](https://github.com/villebase/sopuli-dba/issues/919)) ([e028071](https://github.com/villebase/sopuli-dba/commit/e028071137b6b552fe816d93229af4b478f0a484))
* **output:** print account list row notices in the text output ([#826](https://github.com/villebase/sopuli-dba/issues/826)) ([#920](https://github.com/villebase/sopuli-dba/issues/920)) ([eb15d86](https://github.com/villebase/sopuli-dba/commit/eb15d86260a37e337b2df5a12eb43bbd856268a0))
* **output:** say why account list's date columns are empty ([#921](https://github.com/villebase/sopuli-dba/issues/921)) ([#926](https://github.com/villebase/sopuli-dba/issues/926)) ([d0e4b21](https://github.com/villebase/sopuli-dba/commit/d0e4b21ac58ae808bb4a01fc82c35ec26e7ef988))
* **output:** say why account list's RESET_AT is empty when the journal fails ([#929](https://github.com/villebase/sopuli-dba/issues/929)) ([#936](https://github.com/villebase/sopuli-dba/issues/936)) ([fc15a50](https://github.com/villebase/sopuli-dba/commit/fc15a50559515fc7fe44448512df8765d3905424))
* **store:** keep Vault's reasons when an error entry has several lines ([#934](https://github.com/villebase/sopuli-dba/issues/934)) ([#943](https://github.com/villebase/sopuli-dba/issues/943)) ([5e91968](https://github.com/villebase/sopuli-dba/commit/5e9196863dbc9ddbd5d6d5f0f149594c3133cf54))
* **test:** start the nne and emulators compose profiles ([#937](https://github.com/villebase/sopuli-dba/issues/937)) ([#941](https://github.com/villebase/sopuli-dba/issues/941)) ([9f6b56e](https://github.com/villebase/sopuli-dba/commit/9f6b56e4be1e56a7aaf9f8d092b4e070e979cba5))

## [0.77.0](https://github.com/villebase/sopuli-dba/compare/v0.76.0...v0.77.0) (2026-10-20)


### Features

* **oracle:** map ORA-28009 and print a target's hint in doctor ([#908](https://github.com/villebase/sopuli-dba/issues/908)) ([#911](https://github.com/villebase/sopuli-dba/issues/911)) ([68db8b0](https://github.com/villebase/sopuli-dba/commit/68db8b0c84e2ab95c91ded379f361affc67cc88f)), closes [#909](https://github.com/villebase/sopuli-dba/issues/909)
* **output:** print each result error's hint under a verb's text ([#912](https://github.com/villebase/sopuli-dba/issues/912)) ([#915](https://github.com/villebase/sopuli-dba/issues/915)) ([df133ee](https://github.com/villebase/sopuli-dba/commit/df133ee1c361768caa10861337879603a1d97d09))


### Bug Fixes

* **generate:** keep the reason a target gave no constraints ([#910](https://github.com/villebase/sopuli-dba/issues/910)) ([#913](https://github.com/villebase/sopuli-dba/issues/913)) ([c0a7b66](https://github.com/villebase/sopuli-dba/commit/c0a7b6668513e62a81f201b63f2d03c2c36a78a4))
* **oracle:** point the ORA-28003 hint at --debug ([#792](https://github.com/villebase/sopuli-dba/issues/792)) ([#916](https://github.com/villebase/sopuli-dba/issues/916)) ([f327085](https://github.com/villebase/sopuli-dba/commit/f327085aa88b2b3702a403ab03e4b69350b0c83a))
* **output:** print config warnings under every verb's text ([#897](https://github.com/villebase/sopuli-dba/issues/897)) ([#917](https://github.com/villebase/sopuli-dba/issues/917)) ([4945c81](https://github.com/villebase/sopuli-dba/commit/4945c81eee35b5acc81c0b646854314eb55e43f2))

## [0.76.0](https://github.com/villebase/sopuli-dba/compare/v0.75.0...v0.76.0) (2026-10-19)


### Features

* **config:** warn when VAULT_ADDR overrides a store's declared addr ([#865](https://github.com/villebase/sopuli-dba/issues/865)) ([#889](https://github.com/villebase/sopuli-dba/issues/889)) ([faf4694](https://github.com/villebase/sopuli-dba/commit/faf4694c1f1736f099901f7819503555b4637a48))
* **config:** warn when VAULT_NAMESPACE overrides a store's declared namespace ([#892](https://github.com/villebase/sopuli-dba/issues/892)) ([#894](https://github.com/villebase/sopuli-dba/issues/894)) ([46e306e](https://github.com/villebase/sopuli-dba/commit/46e306e68fed99fe37c546f94b21a6643aa2ffb3))
* give a pipx line beside the pip line when a client is missing ([#902](https://github.com/villebase/sopuli-dba/issues/902)) ([#903](https://github.com/villebase/sopuli-dba/issues/903)) ([2415155](https://github.com/villebase/sopuli-dba/commit/24151553ccb28be9ff82436fa3a8bcfec462ae7b))
* **lock:** warn when lock status skips a lock path it cannot address ([#886](https://github.com/villebase/sopuli-dba/issues/886)) ([#896](https://github.com/villebase/sopuli-dba/issues/896)) ([4d76056](https://github.com/villebase/sopuli-dba/commit/4d76056eb81609f6206175eed35c885264bade96))
* recommend pipx for installing, and run as python -m sopuli ([#900](https://github.com/villebase/sopuli-dba/issues/900)) ([#901](https://github.com/villebase/sopuli-dba/issues/901)) ([2b2131c](https://github.com/villebase/sopuli-dba/commit/2b2131c066ec98c3bb95822533f532d9ba8a351a))
* **store:** add merge_patch: false for a proxy that blocks PATCH ([#904](https://github.com/villebase/sopuli-dba/issues/904)) ([#906](https://github.com/villebase/sopuli-dba/issues/906)) ([f4bca9d](https://github.com/villebase/sopuli-dba/commit/f4bca9d73601501dbdb680d5a4870d85807d6de8))
* **store:** say when a 401 or 403 did not come from Vault ([#905](https://github.com/villebase/sopuli-dba/issues/905)) ([#907](https://github.com/villebase/sopuli-dba/issues/907)) ([114e46e](https://github.com/villebase/sopuli-dba/commit/114e46e4f1c4b4f2cc83b738feb8ee4b90bb4d6b))


### Bug Fixes

* check --vault-token-file through its descriptor before reading it ([#885](https://github.com/villebase/sopuli-dba/issues/885)) ([#888](https://github.com/villebase/sopuli-dba/issues/888)) ([8fd1792](https://github.com/villebase/sopuli-dba/commit/8fd17923a3db3419a5848d576a4dd250a38518d1))
* **config:** refuse ?, %, backslash and control characters in a store path ([#858](https://github.com/villebase/sopuli-dba/issues/858)) ([#883](https://github.com/villebase/sopuli-dba/issues/883)) ([fe45de6](https://github.com/villebase/sopuli-dba/commit/fe45de6caa2f33b5110e76ff3c2d6cd15a3a8374))
* **config:** refuse a POSIX config file owned by another user ([#861](https://github.com/villebase/sopuli-dba/issues/861)) ([#881](https://github.com/villebase/sopuli-dba/issues/881)) ([9cabf76](https://github.com/villebase/sopuli-dba/commit/9cabf762b5c978abe9c51a56eac92c22927543a3))
* **config:** refuse one account declared twice in different case ([#854](https://github.com/villebase/sopuli-dba/issues/854)) ([#871](https://github.com/villebase/sopuli-dba/issues/871)) ([2243afb](https://github.com/villebase/sopuli-dba/commit/2243afbe57c34527a9a28b6db6358c4874ec3e61))
* do not promote an account a guardrail skipped on one of its targets ([#852](https://github.com/villebase/sopuli-dba/issues/852)) ([#870](https://github.com/villebase/sopuli-dba/issues/870)) ([c3ddaae](https://github.com/villebase/sopuli-dba/commit/c3ddaaebe4fee56859b07cdab499293ddbfb5d4d))
* **output:** show control characters from server and vault text ([#859](https://github.com/villebase/sopuli-dba/issues/859)) ([#887](https://github.com/villebase/sopuli-dba/issues/887)) ([54f85b0](https://github.com/villebase/sopuli-dba/commit/54f85b04c44b21ea010aa19c0f16c1feee7b286f))
* **output:** warn on the confirmed rows of a held-back promotion ([#873](https://github.com/villebase/sopuli-dba/issues/873)) ([#880](https://github.com/villebase/sopuli-dba/issues/880)) ([df169b2](https://github.com/villebase/sopuli-dba/commit/df169b239d2f8a77745bad60616d6db8d6e23b02))
* print the plan before the rollback prompt and when a run fails ([#863](https://github.com/villebase/sopuli-dba/issues/863)) ([#895](https://github.com/villebase/sopuli-dba/issues/895)) ([af17c3a](https://github.com/villebase/sopuli-dba/commit/af17c3a1e92cf0c087e989a46f5949bc7b64b487))
* refuse a seen reset when stdin cannot answer the prompt ([#853](https://github.com/villebase/sopuli-dba/issues/853)) ([#875](https://github.com/villebase/sopuli-dba/issues/875)) ([166cc95](https://github.com/villebase/sopuli-dba/commit/166cc9520c15c0a67a65e2fbdcc104d266ddf541))
* refuse creds generate --from-stdin when stdin is a terminal ([#862](https://github.com/villebase/sopuli-dba/issues/862)) ([#893](https://github.com/villebase/sopuli-dba/issues/893)) ([34f1548](https://github.com/villebase/sopuli-dba/commit/34f154841d2ee6856714e4d289acb12e34122b7e))
* renew the lock inside a long target in creds apply ([#864](https://github.com/villebase/sopuli-dba/issues/864)) ([#882](https://github.com/villebase/sopuli-dba/issues/882)) ([a8eb746](https://github.com/villebase/sopuli-dba/commit/a8eb7461dd7ebf805a74c5184f05bffc74f12b2a))

## [0.75.0](https://github.com/villebase/sopuli-dba/compare/v0.74.0...v0.75.0) (2026-10-17)

The first published alpha, and the first release on PyPI. The README's
[Status](https://github.com/villebase/sopuli-dba#status) says what alpha promises,
what is not tested, and which commands are experimental.


### Features

* mark the first published alpha ([#547](https://github.com/villebase/sopuli-dba/issues/547)) ([#849](https://github.com/villebase/sopuli-dba/issues/849)) ([9426294](https://github.com/villebase/sopuli-dba/commit/94262946caffb7867590584f9be3b4b43e7d4cd3))

## [0.74.0](https://github.com/villebase/sopuli-dba/compare/v0.73.0...v0.74.0) (2026-10-17)


### ⚠ BREAKING CHANGES

* **config:** `profiles.<name>.verify`, `profiles.<name>.rotation`, `policies.<name>.verify` and `policies.<name>.rotation` are refused. Delete them, and pass --method, --lockout-margin, --strategy or --max-age-days on the command line instead.

### Features

* **config:** give the config layer's warnings their codes ([#797](https://github.com/villebase/sopuli-dba/issues/797)) ([#821](https://github.com/villebase/sopuli-dba/issues/821)) ([6c44061](https://github.com/villebase/sopuli-dba/commit/6c44061288b3a65ca6c6def5f8047dcf28c35dda))
* **config:** refuse a label key that no target carries ([#819](https://github.com/villebase/sopuli-dba/issues/819)) ([#836](https://github.com/villebase/sopuli-dba/issues/836)) ([0457d88](https://github.com/villebase/sopuli-dba/commit/0457d8844ddfda1e1697f263dc18ff4c8cbe163b))
* **config:** refuse one shared password under two policies ([#830](https://github.com/villebase/sopuli-dba/issues/830)) ([#840](https://github.com/villebase/sopuli-dba/issues/840)) ([21c5938](https://github.com/villebase/sopuli-dba/commit/21c5938d8f7a32becc7ab6a042369abb74416b14))
* **config:** refuse per-account settings in an application entry ([#640](https://github.com/villebase/sopuli-dba/issues/640)) ([#818](https://github.com/villebase/sopuli-dba/issues/818)) ([e5b9987](https://github.com/villebase/sopuli-dba/commit/e5b9987c3457e1cffc341a040aa48361265c21ad))
* **config:** refuse two accounts on one password across entries ([#841](https://github.com/villebase/sopuli-dba/issues/841)) ([#843](https://github.com/villebase/sopuli-dba/issues/843)) ([f83f7c7](https://github.com/villebase/sopuli-dba/commit/f83f7c798f78040c6e29a1ab7ce97a2be0e35bc1))
* **config:** remove the unread verify: and rotation: blocks ([#787](https://github.com/villebase/sopuli-dba/issues/787)) ([#827](https://github.com/villebase/sopuli-dba/issues/827)) ([491497f](https://github.com/villebase/sopuli-dba/commit/491497f8a90e05c3ea6939d336f859b90c72fbfa))
* **creds:** refuse to stage over an existing pending ([#804](https://github.com/villebase/sopuli-dba/issues/804)) ([#808](https://github.com/villebase/sopuli-dba/issues/808)) ([88d0fe4](https://github.com/villebase/sopuli-dba/commit/88d0fe45438cde5a67b355259c5f7fc14bb110d9))
* **doctor:** decide H10, and report the audit roles as over-granted ([#591](https://github.com/villebase/sopuli-dba/issues/591)) ([#810](https://github.com/villebase/sopuli-dba/issues/810)) ([5640305](https://github.com/villebase/sopuli-dba/commit/56403054fdf77a69330db884da8a7ab409350ef1))
* **errors:** give three config errors their codes ([#801](https://github.com/villebase/sopuli-dba/issues/801)) ([#823](https://github.com/villebase/sopuli-dba/issues/823)) ([d06be5d](https://github.com/villebase/sopuli-dba/commit/d06be5db531a876d30640ac43159b7b00e6b6029))
* **output:** give the remaining run warnings their codes ([#798](https://github.com/villebase/sopuli-dba/issues/798)) ([#824](https://github.com/villebase/sopuli-dba/issues/824)) ([5959bf6](https://github.com/villebase/sopuli-dba/commit/5959bf627113b5d14c7a42c1b6b60232212baba2))
* **output:** remove admin.install from the run schema's command enum ([#655](https://github.com/villebase/sopuli-dba/issues/655)) ([#806](https://github.com/villebase/sopuli-dba/issues/806)) ([6921dad](https://github.com/villebase/sopuli-dba/commit/6921daddf7faa7b1f02703435a13ff272aacad7a))
* **reset:** record whether the database audits the DBA's routes ([#591](https://github.com/villebase/sopuli-dba/issues/591)) ([#816](https://github.com/villebase/sopuli-dba/issues/816)) ([2b12890](https://github.com/villebase/sopuli-dba/commit/2b128904001c0de0cbd14368057a6c179bbad787))


### Bug Fixes

* **generate:** draw a password once, however many targets share it ([#830](https://github.com/villebase/sopuli-dba/issues/830)) ([#842](https://github.com/villebase/sopuli-dba/issues/842)) ([f138ec1](https://github.com/villebase/sopuli-dba/commit/f138ec1249f99462b6035022a10e3729cb37ff86))
* keep a library's message out of output where it can quote a secret ([#785](https://github.com/villebase/sopuli-dba/issues/785)) ([#794](https://github.com/villebase/sopuli-dba/issues/794)) ([20deca8](https://github.com/villebase/sopuli-dba/commit/20deca8d4025591eaa5e8adcfb83dc8e9c32bf1e))
* **oracle:** give a COMMON install audit policies that record in its PDBs ([#812](https://github.com/villebase/sopuli-dba/issues/812)) ([#838](https://github.com/villebase/sopuli-dba/issues/838)) ([1483c95](https://github.com/villebase/sopuli-dba/commit/1483c95d635fd8260ba17ca6a43a576671f4cf85))
* **oracle:** map the codes for a lost session and a starting database ([#775](https://github.com/villebase/sopuli-dba/issues/775)) ([#844](https://github.com/villebase/sopuli-dba/issues/844)) ([b015fef](https://github.com/villebase/sopuli-dba/commit/b015fef6f58c1c608230609d2884d2b8be980b5b))
* **output:** say why a run exits 4 when its promotion write fails ([#805](https://github.com/villebase/sopuli-dba/issues/805)) ([#822](https://github.com/villebase/sopuli-dba/issues/822)) ([343e7ca](https://github.com/villebase/sopuli-dba/commit/343e7ca8defb2835a2157557f182f08cd99cc655))
* scrub the password from a refusal that quotes it ([#786](https://github.com/villebase/sopuli-dba/issues/786)) ([#791](https://github.com/villebase/sopuli-dba/issues/791)) ([58d9c1a](https://github.com/villebase/sopuli-dba/commit/58d9c1a3bf523aae06546e1628404d27cadae61e))

## [0.73.0](https://github.com/villebase/sopuli-dba/compare/v0.72.0...v0.73.0) (2026-10-14)


### ⚠ BREAKING CHANGES

* **config:** `profiles.<name>.log_level` and `log_file` are refused. Delete them from the profile.

### Features

* **cli:** --debug writes debug output to stderr ([#781](https://github.com/villebase/sopuli-dba/issues/781)) ([#784](https://github.com/villebase/sopuli-dba/issues/784)) ([406c620](https://github.com/villebase/sopuli-dba/commit/406c6202ee3ffcd8252518575c9c5cd3eb29e188))
* **config:** delete the profile keys log_level and log_file ([#629](https://github.com/villebase/sopuli-dba/issues/629)) ([#783](https://github.com/villebase/sopuli-dba/issues/783)) ([92a38d9](https://github.com/villebase/sopuli-dba/commit/92a38d91f0aee1528cfb61a1774fb519192c57a9))
* debug lines for why a unit was planned or left alone ([#788](https://github.com/villebase/sopuli-dba/issues/788)) ([#790](https://github.com/villebase/sopuli-dba/issues/790)) ([5cd4b3f](https://github.com/villebase/sopuli-dba/commit/5cd4b3fc6e5c5fdc6e0865ee3ceca20b05ba6778))
* debug lines in the Oracle driver and the vault transport ([#782](https://github.com/villebase/sopuli-dba/issues/782)) ([#789](https://github.com/villebase/sopuli-dba/issues/789)) ([af45484](https://github.com/villebase/sopuli-dba/commit/af45484139872a68baae543fe1e5f846986385e4))


### Bug Fixes

* **oracle:** map ORA-01109 and ORA-12514, a closed PDB's codes ([#766](https://github.com/villebase/sopuli-dba/issues/766)) ([#773](https://github.com/villebase/sopuli-dba/issues/773)) ([fdd046c](https://github.com/villebase/sopuli-dba/commit/fdd046c44273b9fe6796a8b480c34c29e3756424))
* **output:** carry error.retryable into the run document ([#774](https://github.com/villebase/sopuli-dba/issues/774)) ([#777](https://github.com/villebase/sopuli-dba/issues/777)) ([5e25d6d](https://github.com/villebase/sopuli-dba/commit/5e25d6d2054a4818b84d7185dda13517281edd4d))
* **rotate:** report a vault lost at the promotion as exit 4 ([#760](https://github.com/villebase/sopuli-dba/issues/760)) ([#780](https://github.com/villebase/sopuli-dba/issues/780)) ([f8fe8f4](https://github.com/villebase/sopuli-dba/commit/f8fe8f4cad28cfaec4e8c0fe3109e2785fcb5125))

## [0.72.0](https://github.com/villebase/sopuli-dba/compare/v0.71.0...v0.72.0) (2026-10-12)


### Features

* **output:** emit plan.confirmation_required ([#663](https://github.com/villebase/sopuli-dba/issues/663)) ([#754](https://github.com/villebase/sopuli-dba/issues/754)) ([ea04dfa](https://github.com/villebase/sopuli-dba/commit/ea04dfa5881c42e8c8eca1b47640b1b004e04964))


### Bug Fixes

* **account:** ask a reset's own refusals before a dry run returns ([#671](https://github.com/villebase/sopuli-dba/issues/671)) ([#751](https://github.com/villebase/sopuli-dba/issues/751)) ([773bbf6](https://github.com/villebase/sopuli-dba/commit/773bbf6974d06fb88b77b0041ce5747a4ea5a958))
* **account:** show each seen-path password on its own target ([#741](https://github.com/villebase/sopuli-dba/issues/741)) ([#752](https://github.com/villebase/sopuli-dba/issues/752)) ([0d70a3c](https://github.com/villebase/sopuli-dba/commit/0d70a3c589813783c42482baf1cf34844d91f515))

## [0.71.0](https://github.com/villebase/sopuli-dba/compare/v0.70.0...v0.71.0) (2026-10-11)


### ⚠ BREAKING CHANGES

* **config:** drop $ and ^ from the alnum_safe charset ([#742](https://github.com/villebase/sopuli-dba/issues/742)) (#744)

### Features

* **doctor:** report whether each connection is encrypted ([#697](https://github.com/villebase/sopuli-dba/issues/697)) ([#736](https://github.com/villebase/sopuli-dba/issues/736)) ([fb2957f](https://github.com/villebase/sopuli-dba/commit/fb2957fc558ea54ff23cacdc458879194b8cd4d0))
* **output:** warn when a password is sent over an unencrypted connection ([#697](https://github.com/villebase/sopuli-dba/issues/697)) ([#737](https://github.com/villebase/sopuli-dba/issues/737)) ([f00afe8](https://github.com/villebase/sopuli-dba/commit/f00afe8d459ae2c7fc5bfe66bdf510d15d7e3058))
* refuse a mutating verb at plan time when a target would prompt ([#481](https://github.com/villebase/sopuli-dba/issues/481)) ([#706](https://github.com/villebase/sopuli-dba/issues/706)) ([91ba57e](https://github.com/villebase/sopuli-dba/commit/91ba57e60b8872fd07489bb4947165a794831440))


### Bug Fixes

* **apply:** keep the row of an account changed before a lost lock ([#739](https://github.com/villebase/sopuli-dba/issues/739)) ([#749](https://github.com/villebase/sopuli-dba/issues/749)) ([bbc505d](https://github.com/villebase/sopuli-dba/commit/bbc505d71cf622a9ae7cfb4f202f95aa2e03cd5c))
* **config:** drop $ and ^ from the alnum_safe charset ([#742](https://github.com/villebase/sopuli-dba/issues/742)) ([#744](https://github.com/villebase/sopuli-dba/issues/744)) ([974c301](https://github.com/villebase/sopuli-dba/commit/974c30113dc445cc12f38605cec00c9473ae73e0))
* drop issue numbers from three runtime strings ([#718](https://github.com/villebase/sopuli-dba/issues/718)) ([#730](https://github.com/villebase/sopuli-dba/issues/730)) ([7a9d0ab](https://github.com/villebase/sopuli-dba/commit/7a9d0ab61329c60cffead29cc4dd195b5121c3d0))
* **lock:** complete binding stores from profile and SOPULI_VAULT in lock status ([#672](https://github.com/villebase/sopuli-dba/issues/672)) ([#676](https://github.com/villebase/sopuli-dba/issues/676)) ([ae5b4ae](https://github.com/villebase/sopuli-dba/commit/ae5b4ae8c61b3aac4fd410d1bbc0c2bbce461181))
* **reset:** print the notes when a seen-path prompt is declined ([#738](https://github.com/villebase/sopuli-dba/issues/738)) ([#740](https://github.com/villebase/sopuli-dba/issues/740)) ([c16ec68](https://github.com/villebase/sopuli-dba/commit/c16ec6804c6fa9b4c1ecc17ef7f91e576b4634d2))

## [0.70.0](https://github.com/villebase/sopuli-dba/compare/v0.69.0...v0.70.0) (2026-10-06)


### ⚠ BREAKING CHANGES

* **output:** register the redraw diagnostics as SOPULI-W029 and W030 ([#610](https://github.com/villebase/sopuli-dba/issues/610)) (#630)

### Features

* **config:** a profile's confirm: false refuses every prompt ([#610](https://github.com/villebase/sopuli-dba/issues/610)) ([#633](https://github.com/villebase/sopuli-dba/issues/633)) ([2fd3eff](https://github.com/villebase/sopuli-dba/commit/2fd3effff29235a70b7bc59f2aa2cbe83521a427))
* **config:** warn that a policy's rotation and verify keys are not read ([#610](https://github.com/villebase/sopuli-dba/issues/610)) ([#631](https://github.com/villebase/sopuli-dba/issues/631)) ([05da179](https://github.com/villebase/sopuli-dba/commit/05da179bd1765794339fb77b89e29a1b455b0dbf))
* **output:** register the redraw diagnostics as SOPULI-W029 and W030 ([#610](https://github.com/villebase/sopuli-dba/issues/610)) ([#630](https://github.com/villebase/sopuli-dba/issues/630)) ([c37a19e](https://github.com/villebase/sopuli-dba/commit/c37a19e74455649f5d29a76cb7ee6345f4293d00))


### Bug Fixes

* **docs:** correct help text, hints and docs that contradict the build ([#609](https://github.com/villebase/sopuli-dba/issues/609)) ([#628](https://github.com/villebase/sopuli-dba/issues/628)) ([a80b0a6](https://github.com/villebase/sopuli-dba/commit/a80b0a6718c2797c171f1dbfe5b3073c4c399754))

## [0.69.0](https://github.com/villebase/sopuli-dba/compare/v0.68.0...v0.69.0) (2026-10-02)


### Features

* **apply:** warn about a reuse-restricted rollback under --preflight ([#580](https://github.com/villebase/sopuli-dba/issues/580)) ([#605](https://github.com/villebase/sopuli-dba/issues/605)) ([fd22c6e](https://github.com/villebase/sopuli-dba/commit/fd22c6e2c89ae5333b4b2b69779e0d9042660a4d))


### Bug Fixes

* **admin:** refuse an empty auth: prompt answer before connecting ([#601](https://github.com/villebase/sopuli-dba/issues/601)) ([#603](https://github.com/villebase/sopuli-dba/issues/603)) ([7f9d4a9](https://github.com/villebase/sopuli-dba/commit/7f9d4a9ed3347437aac33dc1de5ba4d27d79fabf))
* **doctor:** the vault survey shares the run's store clients ([#489](https://github.com/villebase/sopuli-dba/issues/489)) ([#607](https://github.com/villebase/sopuli-dba/issues/607)) ([d5c4326](https://github.com/villebase/sopuli-dba/commit/d5c43265896f40e133bb59e8877220b04250d197))
* **generate:** name the target in the byte-limit refusal ([#598](https://github.com/villebase/sopuli-dba/issues/598)) ([#602](https://github.com/villebase/sopuli-dba/issues/602)) ([a63e9cc](https://github.com/villebase/sopuli-dba/commit/a63e9cce9da0749894f3fcd9742ae1cdceb4897f))
* **preflight:** print a passing survey's caveats in text mode ([#606](https://github.com/villebase/sopuli-dba/issues/606)) ([#608](https://github.com/villebase/sopuli-dba/issues/608)) ([6e479d2](https://github.com/villebase/sopuli-dba/commit/6e479d2710101cf1f2178fc9b49ad86e8da95b31))

## [0.68.0](https://github.com/villebase/sopuli-dba/compare/v0.67.4...v0.68.0) (2026-10-02)


### Features

* **cli:** creds check --method login|hash|both ([#437](https://github.com/villebase/sopuli-dba/issues/437)) ([#600](https://github.com/villebase/sopuli-dba/issues/600)) ([a91fdf7](https://github.com/villebase/sopuli-dba/commit/a91fdf75f9e6b268211a614576c0a239d731b757))
* **oracle:** both, plan-time require_verifier and ADB's own refusal ([#437](https://github.com/villebase/sopuli-dba/issues/437)) ([#599](https://github.com/villebase/sopuli-dba/issues/599)) ([8a7efea](https://github.com/villebase/sopuli-dba/commit/8a7efeaecf3abe5c72cb236f5f33b5eba85ca24d))
* **oracle:** compare a password with the stored 12C verifier ([#437](https://github.com/villebase/sopuli-dba/issues/437)) ([#597](https://github.com/villebase/sopuli-dba/issues/597)) ([4f88fbe](https://github.com/villebase/sopuli-dba/commit/4f88fbe538bc94139d1656e1b36c56f14426ca78))


### Bug Fixes

* **oracle:** key the password byte limit to 23, not 12.2 ([#595](https://github.com/villebase/sopuli-dba/issues/595)) ([#596](https://github.com/villebase/sopuli-dba/issues/596)) ([273cba0](https://github.com/villebase/sopuli-dba/commit/273cba05c926ecafa499bb89567517356ae496db))

## [0.67.4](https://github.com/villebase/sopuli-dba/compare/v0.67.3...v0.67.4) (2026-10-01)


### Bug Fixes

* **rollover:** read PASSWORD_ROLLOVER_TIME in seconds as well as days ([#583](https://github.com/villebase/sopuli-dba/issues/583)) ([#587](https://github.com/villebase/sopuli-dba/issues/587)) ([9c66017](https://github.com/villebase/sopuli-dba/commit/9c66017591b931773311d57eb060611e69e5c8d8))

## [0.67.3](https://github.com/villebase/sopuli-dba/compare/v0.67.2...v0.67.3) (2026-10-01)


### Bug Fixes

* **apply:** say why a rollback meets a reuse-restricted profile ([#568](https://github.com/villebase/sopuli-dba/issues/568)) ([#579](https://github.com/villebase/sopuli-dba/issues/579)) ([753420c](https://github.com/villebase/sopuli-dba/commit/753420ced17f725691c4fd41191fd2b1834ca9dd))
* **apply:** withhold a promotion the run was narrowed past ([#406](https://github.com/villebase/sopuli-dba/issues/406)) ([#578](https://github.com/villebase/sopuli-dba/issues/578)) ([32baed6](https://github.com/villebase/sopuli-dba/commit/32baed6d479c1411beabaa43f969218117de7cb0))
* **oracle:** give thick mode its three reasons and stop saying OCI requires NNE ([#574](https://github.com/villebase/sopuli-dba/issues/574)) ([#576](https://github.com/villebase/sopuli-dba/issues/576)) ([2f000f1](https://github.com/villebase/sopuli-dba/commit/2f000f118b01502b5c5310dba3a75d2c99a158de))

## [0.67.2](https://github.com/villebase/sopuli-dba/compare/v0.67.1...v0.67.2) (2026-09-27)


### Bug Fixes

* **check:** keep "the lockout guard is unavailable" on a login that passes ([#558](https://github.com/villebase/sopuli-dba/issues/558)) ([#559](https://github.com/villebase/sopuli-dba/issues/559)) ([090d71b](https://github.com/villebase/sopuli-dba/commit/090d71b689186d7b151f52a4d7b153a12470ff25))

## [0.67.1](https://github.com/villebase/sopuli-dba/compare/v0.67.0...v0.67.1) (2026-09-26)


### Bug Fixes

* **output:** on Windows, count a stream as a terminal only if it is a console ([#549](https://github.com/villebase/sopuli-dba/issues/549)) ([#550](https://github.com/villebase/sopuli-dba/issues/550)) ([e558743](https://github.com/villebase/sopuli-dba/commit/e5587430b90ea5a26c4bd83b7e0811d36df41779))

## [0.67.0](https://github.com/villebase/sopuli-dba/compare/v0.66.0...v0.67.0) (2026-09-26)


### Features

* **output:** `--output jsonl`, streamed by `creds check` ([#9](https://github.com/villebase/sopuli-dba/issues/9)) ([#534](https://github.com/villebase/sopuli-dba/issues/534)) ([d98fd17](https://github.com/villebase/sopuli-dba/commit/d98fd17cdf1c181a9660d8aa9dd479497862bcfa))
* **output:** stream `account reset-password` under `--output jsonl` ([#535](https://github.com/villebase/sopuli-dba/issues/535)) ([#546](https://github.com/villebase/sopuli-dba/issues/546)) ([a660276](https://github.com/villebase/sopuli-dba/commit/a660276ba969455c4400107765984e63d99ddb82))
* **output:** stream `creds apply` under `--output jsonl` ([#535](https://github.com/villebase/sopuli-dba/issues/535)) ([#542](https://github.com/villebase/sopuli-dba/issues/542)) ([95c868b](https://github.com/villebase/sopuli-dba/commit/95c868b678c89e8623484aea7628f9951d1335c2))
* **output:** stream `creds generate` under `--output jsonl` ([#535](https://github.com/villebase/sopuli-dba/issues/535)) ([#544](https://github.com/villebase/sopuli-dba/issues/544)) ([4a9e7a5](https://github.com/villebase/sopuli-dba/commit/4a9e7a51c69fa2a33e895d563b3fa3c766e0e0d6))
* **output:** stream `creds rotate` under `--output jsonl` ([#535](https://github.com/villebase/sopuli-dba/issues/535)) ([#543](https://github.com/villebase/sopuli-dba/issues/543)) ([68509a0](https://github.com/villebase/sopuli-dba/commit/68509a05bfc13a8d0c7fd6178451a4ff34e8e350))


### Bug Fixes

* **expire:** don't count a close-only partial row as expired in the closing line ([#537](https://github.com/villebase/sopuli-dba/issues/537)) ([#539](https://github.com/villebase/sopuli-dba/issues/539)) ([92d2123](https://github.com/villebase/sopuli-dba/commit/92d21235142b02d0f29598f1f73e50b27bdae910))
* **oracle:** grant DBA_ROLES and gate role predicates on role_lookup ([#531](https://github.com/villebase/sopuli-dba/issues/531)) ([#533](https://github.com/villebase/sopuli-dba/issues/533)) ([addeb6d](https://github.com/villebase/sopuli-dba/commit/addeb6d07b23475a3f56ea2e76973f63d60b432c))
* **oracle:** surface dictionary read failures and refuse a read-only rollover finish ([#521](https://github.com/villebase/sopuli-dba/issues/521)) ([#530](https://github.com/villebase/sopuli-dba/issues/530)) ([804f02f](https://github.com/villebase/sopuli-dba/commit/804f02f0f3ae5de0035002165ad05c135c1e4db2))
* **reset:** report a partly-applied reset as changed, and hand over a live password ([#528](https://github.com/villebase/sopuli-dba/issues/528)) ([#536](https://github.com/villebase/sopuli-dba/issues/536)) ([b38cce7](https://github.com/villebase/sopuli-dba/commit/b38cce7944b9fb3c04e9661e54e1adef4e5a763c))

## [0.66.0](https://github.com/villebase/sopuli-dba/compare/v0.65.0...v0.66.0) (2026-09-25)


### Features

* `sopuli account expire-password`, forcing a change without setting a password ([#525](https://github.com/villebase/sopuli-dba/issues/525)) ([#527](https://github.com/villebase/sopuli-dba/issues/527)) ([a05ef27](https://github.com/villebase/sopuli-dba/commit/a05ef276f53f89dbc2534ad42078ba735d2d79f3))
* **driver:** expire a password without setting one, closing an open window first ([#525](https://github.com/villebase/sopuli-dba/issues/525)) ([#526](https://github.com/villebase/sopuli-dba/issues/526)) ([24dbb8a](https://github.com/villebase/sopuli-dba/commit/24dbb8a3138ba772ea8c9257295ac02b43783f52))
* **notify:** `notify.method: webhook`, UC-2's shared notify channel ([#442](https://github.com/villebase/sopuli-dba/issues/442)) ([#520](https://github.com/villebase/sopuli-dba/issues/520)) ([6925161](https://github.com/villebase/sopuli-dba/commit/69251615cfd0833de8a601c31d034ebf49761ab7))

## [0.65.0](https://github.com/villebase/sopuli-dba/compare/v0.64.0...v0.65.0) (2026-09-22)


### Features

* `sopuli account reset-password`, UC-2's seen path under five guards ([#441](https://github.com/villebase/sopuli-dba/issues/441)) ([#507](https://github.com/villebase/sopuli-dba/issues/507)) ([981d009](https://github.com/villebase/sopuli-dba/commit/981d00959abb113b1a3d1d8b8373d99bd5a64164))
* **delivery:** `vault_wrapped`, UC-2's unseen path ([#444](https://github.com/villebase/sopuli-dba/issues/444), part 1 of 2) ([#518](https://github.com/villebase/sopuli-dba/issues/518)) ([d41693c](https://github.com/villebase/sopuli-dba/commit/d41693cdfaa3457db71027f5d0e9e7ec04d2eb3e))
* **delivery:** the hand-over receipt ([#444](https://github.com/villebase/sopuli-dba/issues/444), part 2 of 2) ([#519](https://github.com/villebase/sopuli-dba/issues/519)) ([c1acce1](https://github.com/villebase/sopuli-dba/commit/c1acce1092338ae3639bf497bdbad2a93aa6b2e5))
* **driver:** reset a personal account's password, UC-2 §4.1's three statements ([#441](https://github.com/villebase/sopuli-dba/issues/441)) ([#504](https://github.com/villebase/sopuli-dba/issues/504)) ([1c4aa09](https://github.com/villebase/sopuli-dba/commit/1c4aa09b82ccf3be87789c71b6a68ddb4772cd41))
* **reset:** take UC-2's advisory lock on the reset record's path ([#512](https://github.com/villebase/sopuli-dba/issues/512)) ([#515](https://github.com/villebase/sopuli-dba/issues/515)) ([3871cc6](https://github.com/villebase/sopuli-dba/commit/3871cc67f28ccb641969428e4a87e119cfed8fb6))
* **reset:** write UC-2's reset record, and say so when there is none ([#511](https://github.com/villebase/sopuli-dba/issues/511)) ([#513](https://github.com/villebase/sopuli-dba/issues/513)) ([1872d86](https://github.com/villebase/sopuli-dba/commit/1872d8602c8b9e63f160f33742176ac0df28e065))
* **settings:** `safety.delivery.allowed_methods`, the fourth ratchet shape ([#498](https://github.com/villebase/sopuli-dba/issues/498)) ([#500](https://github.com/villebase/sopuli-dba/issues/500)) ([d4f48ba](https://github.com/villebase/sopuli-dba/commit/d4f48ba0b64817e6ccb59ef4540295577ee6233a))


### Bug Fixes

* **config:** refuse a null `safety:` block and a null `confirm_environments` ([#501](https://github.com/villebase/sopuli-dba/issues/501)) ([#508](https://github.com/villebase/sopuli-dba/issues/508)) ([4ec02da](https://github.com/villebase/sopuli-dba/commit/4ec02da5ddf53072d18b2b7e13f8ff5c19a6b371))
* **lock:** survey UC-2's reset locks by listing the declared prefix ([#514](https://github.com/villebase/sopuli-dba/issues/514)) ([#517](https://github.com/villebase/sopuli-dba/issues/517)) ([cfa1b2c](https://github.com/villebase/sopuli-dba/commit/cfa1b2c7e11b00fb479e39e52134a6363ca9808f))

## [0.64.0](https://github.com/villebase/sopuli-dba/compare/v0.63.0...v0.64.0) (2026-09-18)


### Features

* `sopuli account list`, the verb H1 owed ([#490](https://github.com/villebase/sopuli-dba/issues/490)) ([#493](https://github.com/villebase/sopuli-dba/issues/493)) ([ba78c82](https://github.com/villebase/sopuli-dba/commit/ba78c82c6559b9d10cc0218acd4c7d3b0b35306e))
* **config:** the `delivery:` block, UC-2's handover ([#440](https://github.com/villebase/sopuli-dba/issues/440)) ([#499](https://github.com/villebase/sopuli-dba/issues/499)) ([2f0ee29](https://github.com/villebase/sopuli-dba/commit/2f0ee2990e56defebc08d1cb819f387b4d7d7cc1))
* **config:** the `reset_records:` block, and the record a reset writes ([#468](https://github.com/villebase/sopuli-dba/issues/468)) ([#491](https://github.com/villebase/sopuli-dba/issues/491)) ([5852894](https://github.com/villebase/sopuli-dba/commit/5852894ece73d0ae6ae75982c79502135c346e10))

## [0.63.0](https://github.com/villebase/sopuli-dba/compare/v0.62.0...v0.63.0) (2026-09-18)


### Features

* `sopuli account suspend`, UC-2's offboarding verb ([#463](https://github.com/villebase/sopuli-dba/issues/463)) ([#480](https://github.com/villebase/sopuli-dba/issues/480)) ([68e5264](https://github.com/villebase/sopuli-dba/commit/68e52648dc2b329a41bce1871371dc492005b10f))
* **config:** the `personal_accounts:` block, by name or by predicate ([#467](https://github.com/villebase/sopuli-dba/issues/467)) ([#473](https://github.com/villebase/sopuli-dba/issues/473)) ([52baa5d](https://github.com/villebase/sopuli-dba/commit/52baa5dd449bd9f85d03ee2d59c3715fd8c66f9d))
* **driver:** ALTER USER ACCOUNT LOCK, and who a personal account is declared by ([#463](https://github.com/villebase/sopuli-dba/issues/463)) ([#475](https://github.com/villebase/sopuli-dba/issues/475)) ([e6de5ee](https://github.com/villebase/sopuli-dba/commit/e6de5ee0e4a02fb893aa0b7a23b42718f3681700))
* **output:** flag the low-assurance admin source, SOPULI-W022 ([#477](https://github.com/villebase/sopuli-dba/issues/477)) ([#487](https://github.com/villebase/sopuli-dba/issues/487)) ([a3c97f6](https://github.com/villebase/sopuli-dba/commit/a3c97f642df8c42b601842aab92a9497f1a8ace7))


### Bug Fixes

* **cli:** build a prompter, so `auth: prompt` can prompt ([#476](https://github.com/villebase/sopuli-dba/issues/476)) ([#482](https://github.com/villebase/sopuli-dba/issues/482)) ([c555e22](https://github.com/villebase/sopuli-dba/commit/c555e22e7af9ced6cf1d884bc891f97f4bc0789c))
* **cli:** supply the store, so `auth: { method: vault }` resolves ([#483](https://github.com/villebase/sopuli-dba/issues/483)) ([#488](https://github.com/villebase/sopuli-dba/issues/488)) ([84effb2](https://github.com/villebase/sopuli-dba/commit/84effb2cef63d8008edcb06f4a77d94e876de28d))

## [0.62.0](https://github.com/villebase/sopuli-dba/compare/v0.61.0...v0.62.0) (2026-09-15)


### Features

* add `--vault-addr`, layer 1 of `vaults.*.addr` ([#427](https://github.com/villebase/sopuli-dba/issues/427)) ([2224787](https://github.com/villebase/sopuli-dba/commit/22247872473a4aa4ded51bf086eac24525b6dcdb))
* add `sopuli about`, the one command that is not a run ([#413](https://github.com/villebase/sopuli-dba/issues/413)) ([#414](https://github.com/villebase/sopuli-dba/issues/414)) ([9979a6c](https://github.com/villebase/sopuli-dba/commit/9979a6c59a5f76ac478912ca805406bde5cfe93d))
* add a stderr spinner, on the one call that actually waits ([#419](https://github.com/villebase/sopuli-dba/issues/419)) ([#420](https://github.com/villebase/sopuli-dba/issues/420)) ([20be635](https://github.com/villebase/sopuli-dba/commit/20be6354821d1bb17749e70b2c66039937e7d073))
* enforce a `safety:` block written on a target, a group or a target set ([#425](https://github.com/villebase/sopuli-dba/issues/425)) ([fc85d89](https://github.com/villebase/sopuli-dba/commit/fc85d89d336be46a42aa5bd15ec91185504d43a5))
* read the password change date from SYS.USER$.PTIME where DBA_USERS lacks it, and say why when it is absent ([#386](https://github.com/villebase/sopuli-dba/issues/386)) ([#421](https://github.com/villebase/sopuli-dba/issues/421)) ([9887d7d](https://github.com/villebase/sopuli-dba/commit/9887d7d7a8a2eb2896fc97b1f5e50c06dcd2bf82))
* report every `safety:` block in `config show`, and per target in JSON ([#429](https://github.com/villebase/sopuli-dba/issues/429)) ([8692bb0](https://github.com/villebase/sopuli-dba/commit/8692bb0a061d2b277135750c9af28f960653b516))
* report which layer supplied each of a store's settings ([#428](https://github.com/villebase/sopuli-dba/issues/428)) ([#430](https://github.com/villebase/sopuli-dba/issues/430)) ([85f67bf](https://github.com/villebase/sopuli-dba/commit/85f67bffea406914a932d6ad7761d0bb26cd72ff))

## [0.61.0](https://github.com/villebase/sopuli-dba/compare/v0.60.0...v0.61.0) (2026-09-11)


### Features

* creds apply --repair FILE, acting only on a run's unconfirmed set ([#405](https://github.com/villebase/sopuli-dba/issues/405)) ([4b0f922](https://github.com/villebase/sopuli-dba/commit/4b0f9225396dda2e0b032e993f02490e7d39db7c))
* emit invocation.config_files, and add an (account, target) filter ([#403](https://github.com/villebase/sopuli-dba/issues/403)) ([55b602d](https://github.com/villebase/sopuli-dba/commit/55b602ddf601f4a421ccc86424a461de050172bd))
* remove `creds.promote` from the run schema, and strike the flags that never existed ([#392](https://github.com/villebase/sopuli-dba/issues/392)) ([#408](https://github.com/villebase/sopuli-dba/issues/408)) ([56ab566](https://github.com/villebase/sopuli-dba/commit/56ab56692d8dc52b2ba3dc33db7c5d59aad215d3))

## [0.60.0](https://github.com/villebase/sopuli-dba/compare/v0.59.0...v0.60.0) (2026-09-10)


### Features

* paint the five views that had no colour at all ([#398](https://github.com/villebase/sopuli-dba/issues/398)) ([13bef22](https://github.com/villebase/sopuli-dba/commit/13bef22df8e9d326ef60ad4dc4db34a91bf9fe9a))

## [0.59.0](https://github.com/villebase/sopuli-dba/compare/v0.58.0...v0.59.0) (2026-09-09)


### Features

* one palette for result states, and one function that decides it ([#396](https://github.com/villebase/sopuli-dba/issues/396)) ([e1f7beb](https://github.com/villebase/sopuli-dba/commit/e1f7beb77acf607bdf40c2622d4eed03a56417c5))


### Bug Fixes

* arrange the compare-and-set guarantee on a lock path, do not just read it ([#393](https://github.com/villebase/sopuli-dba/issues/393)) ([760e584](https://github.com/villebase/sopuli-dba/commit/760e58475b02a81d3377cb997850abbdf6e2344e))

## [0.58.0](https://github.com/villebase/sopuli-dba/compare/v0.57.3...v0.58.0) (2026-09-06)


### Features

* **oracle:** audit SYSDBA and SYSOPER where V$PWFILE_USERS is readable ([#366](https://github.com/villebase/sopuli-dba/issues/366)) ([6b25da0](https://github.com/villebase/sopuli-dba/commit/6b25da0bd4179ab00b0e7f604ef9a2c0a8e3dbda))

## [0.57.3](https://github.com/villebase/sopuli-dba/compare/v0.57.2...v0.57.3) (2026-09-06)


### Bug Fixes

* **config:** import the package's re-exports on demand ([#363](https://github.com/villebase/sopuli-dba/issues/363)) ([#365](https://github.com/villebase/sopuli-dba/issues/365)) ([d68d526](https://github.com/villebase/sopuli-dba/commit/d68d526590d16a0bc77a4788d1d640a07c98568d))
* **config:** move `normalise_path` to the ref grammar that owns it ([#357](https://github.com/villebase/sopuli-dba/issues/357)) ([#364](https://github.com/villebase/sopuli-dba/issues/364)) ([777758a](https://github.com/villebase/sopuli-dba/commit/777758a3d4ad16077b64fadc46b0e32762c9f0c9))
* **config:** wire both `db` budgets to the driver ([#360](https://github.com/villebase/sopuli-dba/issues/360)) ([#361](https://github.com/villebase/sopuli-dba/issues/361)) ([b820c0a](https://github.com/villebase/sopuli-dba/commit/b820c0abaedd488c580fd8c5963f7d59115ff2e9))

## [0.57.2](https://github.com/villebase/sopuli-dba/compare/v0.57.1...v0.57.2) (2026-09-06)


### Bug Fixes

* **apply:** fence the attribute pass and the rollover close ([#347](https://github.com/villebase/sopuli-dba/issues/347)) ([#353](https://github.com/villebase/sopuli-dba/issues/353)) ([5b20400](https://github.com/villebase/sopuli-dba/commit/5b20400a2b7ddbad1e68d35b3c198c8c49808791))
* **lock:** give back the locks already taken when acquisition fails ([#345](https://github.com/villebase/sopuli-dba/issues/345)) ([#350](https://github.com/villebase/sopuli-dba/issues/350)) ([7a09372](https://github.com/villebase/sopuli-dba/commit/7a093723596369342eba452e2182ab9b33696711))
* **lock:** let `lock status` survey a slice past a binding with no store ([#349](https://github.com/villebase/sopuli-dba/issues/349)) ([#355](https://github.com/villebase/sopuli-dba/issues/355)) ([768d4a5](https://github.com/villebase/sopuli-dba/commit/768d4a5800637d22ab30a12c8bb05f848a3f5f40))
* **lock:** refuse `.` and `..` in a secret path ([#344](https://github.com/villebase/sopuli-dba/issues/344)) ([#351](https://github.com/villebase/sopuli-dba/issues/351)) ([bd4bcce](https://github.com/villebase/sopuli-dba/commit/bd4bccec214232d75d66af32c919b0624c897cde))
* **lock:** report a renewal takeover as one, and a capability refusal as one ([#346](https://github.com/villebase/sopuli-dba/issues/346)) ([#354](https://github.com/villebase/sopuli-dba/issues/354)) ([ea64baa](https://github.com/villebase/sopuli-dba/commit/ea64baa36572110357bb4b2f68985b2b98275ad1))
* **lock:** wire `locking.break_expired` through to the LockManager ([#348](https://github.com/villebase/sopuli-dba/issues/348)) ([#356](https://github.com/villebase/sopuli-dba/issues/356)) ([fe0cf5f](https://github.com/villebase/sopuli-dba/commit/fe0cf5fce7952bc59878f5eeda2e358b3c6e3c54))

## [0.57.1](https://github.com/villebase/sopuli-dba/compare/v0.57.0...v0.57.1) (2026-09-05)


### Bug Fixes

* **guardrails:** read `V$PWFILE_USERS`, and report check 3 when it cannot ([#296](https://github.com/villebase/sopuli-dba/issues/296)) ([#340](https://github.com/villebase/sopuli-dba/issues/340)) ([abc3f62](https://github.com/villebase/sopuli-dba/commit/abc3f6279a97d1a1814802e73025dcc11d0e785e))

## [0.57.0](https://github.com/villebase/sopuli-dba/compare/v0.56.0...v0.57.0) (2026-09-05)


### Features

* **generate:** `--promote` writes `current`, behind `--overwrite-current` ([#257](https://github.com/villebase/sopuli-dba/issues/257)) ([#339](https://github.com/villebase/sopuli-dba/issues/339)) ([e4e5331](https://github.com/villebase/sopuli-dba/commit/e4e5331caf5dc4871082825b307c4002c7a35cab))
* **generate:** report the constraints a draw cannot be bound by ([#317](https://github.com/villebase/sopuli-dba/issues/317)) ([#336](https://github.com/villebase/sopuli-dba/issues/336)) ([6d7159c](https://github.com/villebase/sopuli-dba/commit/6d7159c4eff8bd18a9d4b5a30b1b0110b2d8ba93))

## [0.56.0](https://github.com/villebase/sopuli-dba/compare/v0.55.0...v0.56.0) (2026-09-03)


### Features

* **generate:** read the target's byte limit before drawing ([#317](https://github.com/villebase/sopuli-dba/issues/317)) ([#335](https://github.com/villebase/sopuli-dba/issues/335)) ([d0f2c67](https://github.com/villebase/sopuli-dba/commit/d0f2c67a32f9d4d82f0115107b2cfd902268a92b))
* **oracle:** detect application containers and split the refusal ([#204](https://github.com/villebase/sopuli-dba/issues/204)) ([#333](https://github.com/villebase/sopuli-dba/issues/333)) ([b30b0ff](https://github.com/villebase/sopuli-dba/commit/b30b0ff391842ae513bb8fd799a757d85aaf0332))

## [0.55.0](https://github.com/villebase/sopuli-dba/compare/v0.54.0...v0.55.0) (2026-09-02)


### Features

* **check:** carry a diagnostic the server attached to a successful login ([#328](https://github.com/villebase/sopuli-dba/issues/328)) ([4bd4041](https://github.com/villebase/sopuli-dba/commit/4bd404161401483fc88bdc9a8aece83022133a02))


### Bug Fixes

* **check:** read a grace period apart from a hard expiry ([#324](https://github.com/villebase/sopuli-dba/issues/324)) ([b50d54d](https://github.com/villebase/sopuli-dba/commit/b50d54d74846746beaf7a95b4b52b6848a0b51a7))

## [0.54.0](https://github.com/villebase/sopuli-dba/compare/v0.53.0...v0.54.0) (2026-09-02)


### ⚠ BREAKING CHANGES

* **config:** widen `config validate` to every backend it cannot serve ([#321](https://github.com/villebase/sopuli-dba/issues/321))

### Bug Fixes

* **config:** stop sending `config validate` to `pip` for an unwritten backend ([#319](https://github.com/villebase/sopuli-dba/issues/319)) ([11dc2d1](https://github.com/villebase/sopuli-dba/commit/11dc2d16cac922f7a4af1d96027aba38d96d4df7))
* **config:** widen `config validate` to every backend it cannot serve ([#321](https://github.com/villebase/sopuli-dba/issues/321)) ([0475794](https://github.com/villebase/sopuli-dba/commit/04757946e2814cfd20b5fc9f9134c4d446505cdb))

## [0.53.0](https://github.com/villebase/sopuli-dba/compare/v0.52.0...v0.53.0) (2026-09-01)


### Features

* **apply:** decide when a refused password may be redrawn ([#315](https://github.com/villebase/sopuli-dba/issues/315)) ([cf3f7c9](https://github.com/villebase/sopuli-dba/commit/cf3f7c92d780ac888e694913a2634aedb015a6ac))
* **apply:** draw again when the server refuses the password ([#316](https://github.com/villebase/sopuli-dba/issues/316)) ([aebc69e](https://github.com/villebase/sopuli-dba/commit/aebc69e357840c2d81641a2c18f4d5b29dbbcc0c))
* **vault:** record where a staged password came from ([#313](https://github.com/villebase/sopuli-dba/issues/313)) ([edc9549](https://github.com/villebase/sopuli-dba/commit/edc954949eecef617b8d6a49e88c5ba280408765))

## [0.52.0](https://github.com/villebase/sopuli-dba/compare/v0.51.0...v0.52.0) (2026-09-01)


### Features

* **apply:** profile assignment, the second of UC-1 §5's attributes ([#306](https://github.com/villebase/sopuli-dba/issues/306)) ([dbc52b9](https://github.com/villebase/sopuli-dba/commit/dbc52b97bbe83b797c0db66297a37e6977bb36b5))

## [0.51.0](https://github.com/villebase/sopuli-dba/compare/v0.50.0...v0.51.0) (2026-09-01)


### Features

* **apply:** account unlock, the first of UC-1 §5's attributes ([#304](https://github.com/villebase/sopuli-dba/issues/304)) ([70c05b7](https://github.com/villebase/sopuli-dba/commit/70c05b72349d34d067ea8acd8ac00099b65ab4f4))

## [0.50.0](https://github.com/villebase/sopuli-dba/compare/v0.49.0...v0.50.0) (2026-08-31)


### Features

* **cli:** --target, --account, --group and --application ([#299](https://github.com/villebase/sopuli-dba/issues/299)) ([ee95f07](https://github.com/villebase/sopuli-dba/commit/ee95f0757501b02a041362819098d2caf9d3580d))
* **cli:** creds rotate, the sequence under one lock ([#293](https://github.com/villebase/sopuli-dba/issues/293)) ([f564554](https://github.com/villebase/sopuli-dba/commit/f5645548be7d2bccac83bcf326969368f9b41018))
* **safety:** call the section 4 account guardrails ([#298](https://github.com/villebase/sopuli-dba/issues/298)) ([5cebebb](https://github.com/villebase/sopuli-dba/commit/5cebebb54d271615f9ce5ccd3f8bd97c742a3f5c))
* **safety:** enforce `safety.confirm_environments` ([#295](https://github.com/villebase/sopuli-dba/issues/295)) ([da38969](https://github.com/villebase/sopuli-dba/commit/da38969cad01cb25c79be9515ee11918ffb80b3f))

## [0.49.0](https://github.com/villebase/sopuli-dba/compare/v0.48.0...v0.49.0) (2026-08-31)


### Features

* **cli:** creds apply --preflight, and the estate it asks before writing ([#289](https://github.com/villebase/sopuli-dba/issues/289)) ([43589c2](https://github.com/villebase/sopuli-dba/commit/43589c2f048dea0c2adf550b0d07b01faba1eb0b))
* **cli:** exit 4 names the repair, and where --repair's list will come from ([#280](https://github.com/villebase/sopuli-dba/issues/280)) ([a27dc90](https://github.com/villebase/sopuli-dba/commit/a27dc9093c40f7662fc8405a31c882767a20067f))
* **lock:** re-read the fence before every mutation, and stop when it fails ([#285](https://github.com/villebase/sopuli-dba/issues/285)) ([5f031f2](https://github.com/villebase/sopuli-dba/commit/5f031f271352bd58a65ee6332a629a95d56aac1c))


### Bug Fixes

* **output:** driver errors carry their own category, exit code and capability ([#288](https://github.com/villebase/sopuli-dba/issues/288)) ([1073096](https://github.com/villebase/sopuli-dba/commit/1073096f9a2fb9bfcea55d75ee1f5f910a515067))

## [0.48.0](https://github.com/villebase/sopuli-dba/compare/v0.47.0...v0.48.0) (2026-08-29)


### Features

* **cli:** sopuli creds status, the inventory that spends no logins ([#278](https://github.com/villebase/sopuli-dba/issues/278)) ([dbfdba2](https://github.com/villebase/sopuli-dba/commit/dbfdba243e153e20f82cb433fcb0ef1291f6fbde))

## [0.47.0](https://github.com/villebase/sopuli-dba/compare/v0.46.0...v0.47.0) (2026-08-29)


### Features

* **cli:** creds apply --source, and the rollback it exists for ([#273](https://github.com/villebase/sopuli-dba/issues/273)) ([231cf89](https://github.com/villebase/sopuli-dba/commit/231cf89520a9ba96b5d279cf5707d73cdcaaa6e3))
* **cli:** sopuli creds finish-rollover, and the windows it refuses to close ([#271](https://github.com/villebase/sopuli-dba/issues/271)) ([fd0a135](https://github.com/villebase/sopuli-dba/commit/fd0a1357a846d053370f6e216f8ee35af7813943))

## [0.46.0](https://github.com/villebase/sopuli-dba/compare/v0.45.0...v0.46.0) (2026-08-29)


### Features

* **cli:** creds apply --strategy, and the regime that cannot be honoured ([#269](https://github.com/villebase/sopuli-dba/issues/269)) ([a775939](https://github.com/villebase/sopuli-dba/commit/a775939b398b7175cdd515edbbd4eb16bfdca437))

## [0.45.0](https://github.com/villebase/sopuli-dba/compare/v0.44.0...v0.45.0) (2026-08-29)


### Features

* **cli:** sopuli creds apply, vault to database and the promote after it ([#261](https://github.com/villebase/sopuli-dba/issues/261)) ([00bf92e](https://github.com/villebase/sopuli-dba/commit/00bf92e2a03674269544719d91ece8b3fa5ccb87))
* **cli:** sopuli creds generate, the first credential mutation ([#256](https://github.com/villebase/sopuli-dba/issues/256)) ([50966dd](https://github.com/villebase/sopuli-dba/commit/50966dd31c82339af53e963c9a84bcf16ce30628))
* **config:** refuse two accounts staging into one place at load ([#260](https://github.com/villebase/sopuli-dba/issues/260)) ([ebfeaba](https://github.com/villebase/sopuli-dba/commit/ebfeaba163c8d3937c1182919f3cbeb8c4c41203))

## [0.44.0](https://github.com/villebase/sopuli-dba/compare/v0.43.0...v0.44.0) (2026-08-28)


### Features

* **cli:** sopuli creds check, the first creds verb ([#253](https://github.com/villebase/sopuli-dba/issues/253)) ([887b061](https://github.com/villebase/sopuli-dba/commit/887b0611e5159d265fa4dad3da2a94dab61b2260))
* **config:** complete a binding's store once the run is known ([#252](https://github.com/villebase/sopuli-dba/issues/252)) ([a196797](https://github.com/villebase/sopuli-dba/commit/a19679757deab12352e463c5409f8a7d02a4e2ab))
* **plan:** the plan section, and the max_targets refusal that reads it ([#249](https://github.com/villebase/sopuli-dba/issues/249)) ([a710882](https://github.com/villebase/sopuli-dba/commit/a7108829b344f294169372569f4a939d2f3005c6))

## [0.43.0](https://github.com/villebase/sopuli-dba/compare/v0.42.0...v0.43.0) (2026-08-28)


### Features

* **doctor:** vault reachability and clock skew ([#216](https://github.com/villebase/sopuli-dba/issues/216)) ([#246](https://github.com/villebase/sopuli-dba/issues/246)) ([50750af](https://github.com/villebase/sopuli-dba/commit/50750afc52ff1cfb95e5aedbe471d2149a88637e))
* **store:** health(), and the server clock it reports ([#216](https://github.com/villebase/sopuli-dba/issues/216)) ([#244](https://github.com/villebase/sopuli-dba/issues/244)) ([903f403](https://github.com/villebase/sopuli-dba/commit/903f403d4881053d149df5de2c1bd576cbfe00ea))

## [0.42.0](https://github.com/villebase/sopuli-dba/compare/v0.41.0...v0.42.0) (2026-08-28)


### Features

* **doctor:** the install-shape section, present on every run ([#214](https://github.com/villebase/sopuli-dba/issues/214)) ([#237](https://github.com/villebase/sopuli-dba/issues/237)) ([c374fd4](https://github.com/villebase/sopuli-dba/commit/c374fd47bc509706cdf94badc53359840483877d))
* **doctor:** wallet readability under `auth: external` ([#215](https://github.com/villebase/sopuli-dba/issues/215)) ([#241](https://github.com/villebase/sopuli-dba/issues/241)) ([f4706b6](https://github.com/villebase/sopuli-dba/commit/f4706b600802773b106defa75a26665b5b7475bd))

## [0.41.0](https://github.com/villebase/sopuli-dba/compare/v0.40.0...v0.41.0) (2026-08-26)


### Features

* **doctor:** the positive side of --check-privileges, and schema 1.12 ([#225](https://github.com/villebase/sopuli-dba/issues/225)) ([#227](https://github.com/villebase/sopuli-dba/issues/227)) ([b9bcab4](https://github.com/villebase/sopuli-dba/commit/b9bcab431f4816d52c8e291e4c99ccd65e093184))
* **sql:** pass the operator scripts their parameters ([#229](https://github.com/villebase/sopuli-dba/issues/229)) ([#234](https://github.com/villebase/sopuli-dba/issues/234)) ([65fcea1](https://github.com/villebase/sopuli-dba/commit/65fcea1704380c99107d1c914db6995a59f27a8d))


### Bug Fixes

* **sql:** four bugs in the operator scripts, found by executing them ([#232](https://github.com/villebase/sopuli-dba/issues/232)) ([c3153f7](https://github.com/villebase/sopuli-dba/commit/c3153f74b079e4c9e34d19821996aa9837c16dcb))

## [0.40.0](https://github.com/villebase/sopuli-dba/compare/v0.39.0...v0.40.0) (2026-08-26)


### Features

* **doctor:** --check-privileges — report what the account should not hold ([#213](https://github.com/villebase/sopuli-dba/issues/213)) ([#224](https://github.com/villebase/sopuli-dba/issues/224)) ([33c5853](https://github.com/villebase/sopuli-dba/commit/33c58534b0eb970daceff53cd923f2dcaf5cf64a))
* **store:** read a credential — resolve a SecretRef against a stored document ([#183](https://github.com/villebase/sopuli-dba/issues/183)) ([#221](https://github.com/villebase/sopuli-dba/issues/221)) ([59b32f0](https://github.com/villebase/sopuli-dba/commit/59b32f0150995914c0fbda87e684998b76f759b4))
* **store:** write a credential — a merge patch that leaves siblings alone ([#183](https://github.com/villebase/sopuli-dba/issues/183)) ([#223](https://github.com/villebase/sopuli-dba/issues/223)) ([9bd9153](https://github.com/villebase/sopuli-dba/commit/9bd91537dc7cecbdcb5d6583ef9eb1ce2213e37c))

## [0.39.0](https://github.com/villebase/sopuli-dba/compare/v0.38.0...v0.39.0) (2026-08-22)


### Features

* **cli:** sopuli doctor — connect to every target and mutate nothing ([#182](https://github.com/villebase/sopuli-dba/issues/182)) ([#212](https://github.com/villebase/sopuli-dba/issues/212)) ([8652117](https://github.com/villebase/sopuli-dba/commit/86521174ac2f9d1d1f580aaa3ae39a79fc97820c))
* **driver:** gradual password rollover — the check, the window, the finish ([#181](https://github.com/villebase/sopuli-dba/issues/181)) ([#210](https://github.com/villebase/sopuli-dba/issues/210)) ([1c41882](https://github.com/villebase/sopuli-dba/commit/1c4188270d3b39c472920e9b030c137a3c1e9083))

## [0.38.0](https://github.com/villebase/sopuli-dba/compare/v0.37.0...v0.38.0) (2026-08-22)


### Features

* **driver:** check the scope a target asserts against the one it reached ([#177](https://github.com/villebase/sopuli-dba/issues/177)) ([#206](https://github.com/villebase/sopuli-dba/issues/206)) ([ca4bbdb](https://github.com/villebase/sopuli-dba/commit/ca4bbdbb2ff4dc7ac011649e703a159c172c3fc0))
* **driver:** issue the ALTER USER, and let a rejection be a rejection ([#179](https://github.com/villebase/sopuli-dba/issues/179)) ([#208](https://github.com/villebase/sopuli-dba/issues/208)) ([febc475](https://github.com/villebase/sopuli-dba/commit/febc475b6b5f929c80ffde7610857f678afe92de))
* **driver:** probe capabilities and resolve scope on connect ([#177](https://github.com/villebase/sopuli-dba/issues/177)) ([#203](https://github.com/villebase/sopuli-dba/issues/203)) ([002f946](https://github.com/villebase/sopuli-dba/commit/002f94676a350f737bc3ead464107c267722f0ec))
* **driver:** read an account's state from DBA_USERS and DBA_PROFILES ([#178](https://github.com/villebase/sopuli-dba/issues/178)) ([#207](https://github.com/villebase/sopuli-dba/issues/207)) ([4b21ac5](https://github.com/villebase/sopuli-dba/commit/4b21ac53fe51c3ef2102ce55f301f8b7ca0c2d81))

## [0.37.0](https://github.com/villebase/sopuli-dba/compare/v0.36.0...v0.37.0) (2026-08-21)


### Features

* **driver:** connect in thick mode, with the run's id on the session ([#201](https://github.com/villebase/sopuli-dba/issues/201)) ([0b4a77a](https://github.com/villebase/sopuli-dba/commit/0b4a77ada439b463f29c98e59f0a70a66a6bbff2))

## [0.36.0](https://github.com/villebase/sopuli-dba/compare/v0.35.0...v0.36.0) (2026-08-21)


### Features

* **admin:** resolve the admin credential from P2's four sources ([#196](https://github.com/villebase/sopuli-dba/issues/196)) ([1c38ea2](https://github.com/villebase/sopuli-dba/commit/1c38ea2572b2aab0a9502ac09a04545cbc09452b))

## [0.35.0](https://github.com/villebase/sopuli-dba/compare/v0.34.0...v0.35.0) (2026-08-21)


### Features

* **testing:** capability probing, skip markers and the matrix report ([#192](https://github.com/villebase/sopuli-dba/issues/192)) ([60ba98c](https://github.com/villebase/sopuli-dba/commit/60ba98ccc2f262b8322431cc451b8cbb63057bf8))

## [0.34.0](https://github.com/villebase/sopuli-dba/compare/v0.33.0...v0.34.0) (2026-08-20)


### Features

* **driver:** a driver registry, and the mechanism it shares with stores ([#190](https://github.com/villebase/sopuli-dba/issues/190)) ([3855543](https://github.com/villebase/sopuli-dba/commit/3855543197b735203c7da61fb303961d90baf4f7))

## [0.33.0](https://github.com/villebase/sopuli-dba/compare/v0.32.0...v0.33.0) (2026-08-20)


### Features

* **driver:** the client-side account guardrails, and what `--force` overrides ([#189](https://github.com/villebase/sopuli-dba/issues/189)) ([45b4aae](https://github.com/villebase/sopuli-dba/commit/45b4aae11a8b43171aff04312bb1a99158cdd25d))
* **driver:** the P1 driver interface, as types and vocabulary ([#185](https://github.com/villebase/sopuli-dba/issues/185)) ([13743a1](https://github.com/villebase/sopuli-dba/commit/13743a1f9fe1cd8df622a83cb2ce8fe0ef989d07))
* **oracle:** build ALTER USER directly, and refuse rather than escape ([#187](https://github.com/villebase/sopuli-dba/issues/187)) ([60cfc52](https://github.com/villebase/sopuli-dba/commit/60cfc528d66555ca6fc55cd7521a8773f249995d))
* **oracle:** map ORA- codes to a category, an exit code and a hint ([#188](https://github.com/villebase/sopuli-dba/issues/188)) ([0e7b1ec](https://github.com/villebase/sopuli-dba/commit/0e7b1ecf1f61f48ff6fde34d89d1778fce2215cf))

## [0.32.0](https://github.com/villebase/sopuli-dba/compare/v0.31.0...v0.32.0) (2026-08-20)


### Features

* **lock:** `sopuli lock break` — take a lock from its holder, and fence them ([#167](https://github.com/villebase/sopuli-dba/issues/167)) ([0e698a7](https://github.com/villebase/sopuli-dba/commit/0e698a74c0566bcb980013f4053c02f970912770))

## [0.31.0](https://github.com/villebase/sopuli-dba/compare/v0.30.0...v0.31.0) (2026-08-20)


### Features

* **config:** `SOPULI_VAULT__<NAME>__*` and the layer-3 vault variables ([#165](https://github.com/villebase/sopuli-dba/issues/165)) ([d159d98](https://github.com/villebase/sopuli-dba/commit/d159d98e40091fe46e0d4be794306a82b1f4062f))

## [0.30.0](https://github.com/villebase/sopuli-dba/compare/v0.29.0...v0.30.0) (2026-08-19)


### Features

* **config:** activate a profile, so precedence layer 3 is reachable ([#163](https://github.com/villebase/sopuli-dba/issues/163)) ([654f187](https://github.com/villebase/sopuli-dba/commit/654f18756227d91a07495714918972f69f39d9b5)), closes [#153](https://github.com/villebase/sopuli-dba/issues/153)

## [0.29.0](https://github.com/villebase/sopuli-dba/compare/v0.28.0...v0.29.0) (2026-08-19)


### Features

* **lock:** `lock status` reports records the config does not declare ([#161](https://github.com/villebase/sopuli-dba/issues/161)) ([65ed0a4](https://github.com/villebase/sopuli-dba/commit/65ed0a49b290165caa60b52d5a52948017fb1118))
* **store:** `list(prefix)` on the store protocol, and both KV mounts ([#159](https://github.com/villebase/sopuli-dba/issues/159)) ([070d4bc](https://github.com/villebase/sopuli-dba/commit/070d4bc4cddf6d66c42067d7159239ad02e26714))

## [0.28.0](https://github.com/villebase/sopuli-dba/compare/v0.27.0...v0.28.0) (2026-08-19)


### Features

* **vault:** `--vault-token-file` takes a path; `--vault-token` is refused ([#157](https://github.com/villebase/sopuli-dba/issues/157)) ([2a97b1d](https://github.com/villebase/sopuli-dba/commit/2a97b1d4260b44e5316fddbb89ae851fbf1e6dcc))

## [0.27.0](https://github.com/villebase/sopuli-dba/compare/v0.26.0...v0.27.0) (2026-08-19)


### Features

* **config:** partial `vaults:` blocks, and the file's layers of the merge ([#155](https://github.com/villebase/sopuli-dba/issues/155)) ([5ff9051](https://github.com/villebase/sopuli-dba/commit/5ff90519f370285c542562cb544084cda15ba754))

## [0.26.0](https://github.com/villebase/sopuli-dba/compare/v0.25.0...v0.26.0) (2026-08-19)


### Features

* **lock:** `sopuli lock status` — what is held, by whom, and since when ([#151](https://github.com/villebase/sopuli-dba/issues/151)) ([57b4bcf](https://github.com/villebase/sopuli-dba/commit/57b4bcffa216df8e47c60ba220c8b25040a35fee))

## [0.25.0](https://github.com/villebase/sopuli-dba/compare/v0.24.0...v0.25.0) (2026-08-18)


### Features

* **config:** a vault's transport settings — namespace, timeout_s and tls: ([#141](https://github.com/villebase/sopuli-dba/issues/141)) ([10e683b](https://github.com/villebase/sopuli-dba/commit/10e683b018c0a306231f631d50339f9143904822))
* **packaging:** extras in pyproject, and a store registry that imports lazily ([#139](https://github.com/villebase/sopuli-dba/issues/139)) ([7a8a14e](https://github.com/villebase/sopuli-dba/commit/7a8a14efcbc42572232ff63c70b50df9bb6ff7ca))
* **vault:** HashiCorp auth methods — token, AppRole, Kubernetes, userpass ([#146](https://github.com/villebase/sopuli-dba/issues/146)) ([e16a79e](https://github.com/villebase/sopuli-dba/commit/e16a79eab441bf7148e530b07e9b945013991a8f))
* **vault:** HashiCorp KV v2 store adapter, conformance-tested against the fake ([#142](https://github.com/villebase/sopuli-dba/issues/142)) ([8f3700d](https://github.com/villebase/sopuli-dba/commit/8f3700d05c1f449e1ecb1ec77b33966e9f4b6330))
* **vault:** resolve a MaterialRef to a Secret — env, file, and the token chain ([#144](https://github.com/villebase/sopuli-dba/issues/144)) ([49d2b6d](https://github.com/villebase/sopuli-dba/commit/49d2b6d1189f0f78105c182fb1d2c7ec89ac43ae))


### Bug Fixes

* **test:** race the lock on a handshake, not on a guess about startup time ([#148](https://github.com/villebase/sopuli-dba/issues/148)) ([04b9b84](https://github.com/villebase/sopuli-dba/commit/04b9b841d6158bbe5c9f04b87f6887ebc1fa5bf9))

## [0.24.0](https://github.com/villebase/sopuli-dba/compare/v0.23.0...v0.24.0) (2026-08-18)


### Features

* **config:** decide C15 — refuse a binding with no store only when vaults: is empty ([#126](https://github.com/villebase/sopuli-dba/issues/126)) ([d2faa81](https://github.com/villebase/sopuli-dba/commit/d2faa8156f590ab3b73f77eb9df603588dac266f))

## [0.23.0](https://github.com/villebase/sopuli-dba/compare/v0.22.0...v0.23.0) (2026-08-17)


### Features

* **config:** detect shared secrets, and show them in `config show --resolved` ([#110](https://github.com/villebase/sopuli-dba/issues/110)) ([#117](https://github.com/villebase/sopuli-dba/issues/117)) ([994ce81](https://github.com/villebase/sopuli-dba/commit/994ce81a770664ea4c457d863a3a16b614bb1cbe))
* **config:** refuse an unstageable secret ref while the file is read ([#111](https://github.com/villebase/sopuli-dba/issues/111)) ([#113](https://github.com/villebase/sopuli-dba/issues/113)) ([355bfa4](https://github.com/villebase/sopuli-dba/commit/355bfa4eb0f5508455255403f3bc95d43de81e51))

## [0.22.0](https://github.com/villebase/sopuli-dba/compare/v0.21.0...v0.22.0) (2026-08-17)


### Features

* **payload:** one secret per application by default, one rule for both layouts ([#85](https://github.com/villebase/sopuli-dba/issues/85)) ([#109](https://github.com/villebase/sopuli-dba/issues/109)) ([5cd9b74](https://github.com/villebase/sopuli-dba/commit/5cd9b74c4507f3bc13c98f5b27e99eb25e5e70a1))

## [0.21.0](https://github.com/villebase/sopuli-dba/compare/v0.20.0...v0.21.0) (2026-08-16)


### Features

* **config:** `vaults.*.locking` and `locking.break_expired` ([#83](https://github.com/villebase/sopuli-dba/issues/83)) ([#108](https://github.com/villebase/sopuli-dba/issues/108)) ([4a220d3](https://github.com/villebase/sopuli-dba/commit/4a220d335e51b9e3e90937b0bfcd62676307bd8e))
* **lock:** a LockManager over a narrow store protocol ([#83](https://github.com/villebase/sopuli-dba/issues/83)) ([#101](https://github.com/villebase/sopuli-dba/issues/101)) ([4358348](https://github.com/villebase/sopuli-dba/commit/435834869c25b8f67f3d1824af98f10559604b9c))
* **lock:** the lock record and its state machine, as tier-0 logic ([#83](https://github.com/villebase/sopuli-dba/issues/83)) ([#100](https://github.com/villebase/sopuli-dba/issues/100)) ([476ffc4](https://github.com/villebase/sopuli-dba/commit/476ffc490e923279ffdf20f65e7efbe60e9ab51e))
* **output:** emit the lock section, exit 7, and the first warning codes ([#83](https://github.com/villebase/sopuli-dba/issues/83)) ([#102](https://github.com/villebase/sopuli-dba/issues/102)) ([d0f3872](https://github.com/villebase/sopuli-dba/commit/d0f38725ac918a119536374244c998ab5878c95a))
* **output:** record the Q2 advisory-lock decision, run schema 1.5 ([#98](https://github.com/villebase/sopuli-dba/issues/98)) ([2056398](https://github.com/villebase/sopuli-dba/commit/2056398209a8df4f0a27555f9b40b9dcd3369ed5))

## [0.20.0](https://github.com/villebase/sopuli-dba/compare/v0.19.0...v0.20.0) (2026-08-16)


### ⚠ BREAKING CHANGES

* **config:** decide the SecretRef qualifier vocabularies (C14) ([#92](https://github.com/villebase/sopuli-dba/issues/92))

### Features

* **config:** decide the SecretRef qualifier vocabularies (C14) ([#92](https://github.com/villebase/sopuli-dba/issues/92)) ([5290d6f](https://github.com/villebase/sopuli-dba/commit/5290d6ff85d9b4281db98a9165172bd43c8f9912))

## [0.19.0](https://github.com/villebase/sopuli-dba/compare/v0.18.0...v0.19.0) (2026-08-13)


### Features

* **config:** show where every effective setting came from, with --explain ([#81](https://github.com/villebase/sopuli-dba/issues/81)) ([5ea2318](https://github.com/villebase/sopuli-dba/commit/5ea2318a90ebede6f1e61e1dde186232e816f85b))

## [0.18.0](https://github.com/villebase/sopuli-dba/compare/v0.17.0...v0.18.0) (2026-08-13)


### ⚠ BREAKING CHANGES

* **cli:** split usage from configuration errors, and state J7's rule ([#77](https://github.com/villebase/sopuli-dba/issues/77))

### Features

* **cli:** emit a run document for every exit but 2 ([#79](https://github.com/villebase/sopuli-dba/issues/79)) ([c778eae](https://github.com/villebase/sopuli-dba/commit/c778eaef99df2f575a332b1f89d7eaa9641145e2))
* **cli:** split usage from configuration errors, and state J7's rule ([#77](https://github.com/villebase/sopuli-dba/issues/77)) ([90ccf94](https://github.com/villebase/sopuli-dba/commit/90ccf94e022d5b86586c8917db4cf68423a54e68))

## [0.17.0](https://github.com/villebase/sopuli-dba/compare/v0.16.0...v0.17.0) (2026-08-13)


### Features

* **cli:** resolve every global option through one precedence chain ([#75](https://github.com/villebase/sopuli-dba/issues/75)) ([d91742b](https://github.com/villebase/sopuli-dba/commit/d91742bc34a10f46c18888c94c01565f76f2a233))
* **settings:** resolve a setting across P3's layers, with a safety ratchet ([#73](https://github.com/villebase/sopuli-dba/issues/73)) ([33a64f4](https://github.com/villebase/sopuli-dba/commit/33a64f4f36d18d70a4f9c4a4f5d918257d0c3fa6))

## [0.16.0](https://github.com/villebase/sopuli-dba/compare/v0.15.0...v0.16.0) (2026-08-12)


### Features

* show what a password policy produces, with policy sample ([#69](https://github.com/villebase/sopuli-dba/issues/69)) ([e23c5e7](https://github.com/villebase/sopuli-dba/commit/e23c5e7d4fd7014912adb0e0b4c89c3562183acc)), closes [#68](https://github.com/villebase/sopuli-dba/issues/68)


### Bug Fixes

* **config:** say what to write in a missing auth key, not which one ([#71](https://github.com/villebase/sopuli-dba/issues/71)) ([082cfe1](https://github.com/villebase/sopuli-dba/commit/082cfe10c474c0e07efa615748ac9e9491248b5e)), closes [#70](https://github.com/villebase/sopuli-dba/issues/70)

## [0.15.0](https://github.com/villebase/sopuli-dba/compare/v0.14.0...v0.15.0) (2026-08-12)


### Features

* **config:** adopt the run document's scope vocabulary, as an assertion ([#65](https://github.com/villebase/sopuli-dba/issues/65)) ([ef6c5b0](https://github.com/villebase/sopuli-dba/commit/ef6c5b05d0325f2e1fa5616c0ed4a2049c5e9b9a)), closes [#27](https://github.com/villebase/sopuli-dba/issues/27)
* **config:** name the database admin credential, in the vault grammar ([#64](https://github.com/villebase/sopuli-dba/issues/64)) ([e881c4c](https://github.com/villebase/sopuli-dba/commit/e881c4ca9ac4ad476cf917efbe9c8dc0d57a791a)), closes [#27](https://github.com/villebase/sopuli-dba/issues/27)
* **config:** point at vault auth material with a MaterialRef ([#63](https://github.com/villebase/sopuli-dba/issues/63)) ([274c730](https://github.com/villebase/sopuli-dba/commit/274c73083b2816abc5b0f5236983cc12e08e1d55)), closes [#27](https://github.com/villebase/sopuli-dba/issues/27)
* generate passwords from a policy, as tier 0 logic ([#67](https://github.com/villebase/sopuli-dba/issues/67)) ([c385483](https://github.com/villebase/sopuli-dba/commit/c38548365f50d2e414e3975e05b1a75ed301bf6d)), closes [#58](https://github.com/villebase/sopuli-dba/issues/58)

## [0.14.0](https://github.com/villebase/sopuli-dba/compare/v0.13.0...v0.14.0) (2026-08-12)


### Features

* add target list, the estate as its own command ([#61](https://github.com/villebase/sopuli-dba/issues/61)) ([d925977](https://github.com/villebase/sopuli-dba/commit/d925977476eee614b931a3c0b430ea17b959c6a7))

## [0.13.0](https://github.com/villebase/sopuli-dba/compare/v0.12.1...v0.13.0) (2026-08-12)


### Features

* filter the expanded estate with --select over target labels ([#59](https://github.com/villebase/sopuli-dba/issues/59)) ([ee3bdf8](https://github.com/villebase/sopuli-dba/commit/ee3bdf82bf7303fb349fa64f245dfd9806faf08f))

## [0.12.1](https://github.com/villebase/sopuli-dba/compare/v0.12.0...v0.12.1) (2026-08-12)


### Bug Fixes

* report config warnings as diagnostics from config show ([#54](https://github.com/villebase/sopuli-dba/issues/54)) ([9d0dc7e](https://github.com/villebase/sopuli-dba/commit/9d0dc7e0841b2c462cfcf6c830b4f7faf5c1cbbe))

## [0.12.0](https://github.com/villebase/sopuli-dba/compare/v0.11.0...v0.12.0) (2026-08-11)


### Features

* **config:** publish the config JSON Schema, generated from the model ([#49](https://github.com/villebase/sopuli-dba/issues/49)) ([a3ee3f9](https://github.com/villebase/sopuli-dba/commit/a3ee3f90f8fd70f1566415b5a5b820afbd74f3e5))

## [0.11.0](https://github.com/villebase/sopuli-dba/compare/v0.10.0...v0.11.0) (2026-08-11)


### Features

* colour the text output, semantically ([#47](https://github.com/villebase/sopuli-dba/issues/47)) ([b38e13a](https://github.com/villebase/sopuli-dba/commit/b38e13ac11ccf7157fdf4ef88dc612e3ea52a878))

## [0.10.0](https://github.com/villebase/sopuli-dba/compare/v0.9.0...v0.10.0) (2026-08-11)


### Features

* bind accounts to targets, and resolve every secret ref ([#43](https://github.com/villebase/sopuli-dba/issues/43)) ([7848b54](https://github.com/villebase/sopuli-dba/commit/7848b54455462c5aaf530c3fdf046ed751642177))
* render config show, as loaded and as resolved ([#45](https://github.com/villebase/sopuli-dba/issues/45)) ([83108a7](https://github.com/villebase/sopuli-dba/commit/83108a779336546464de960fa194edfb8f6dac88))

## [0.9.0](https://github.com/villebase/sopuli-dba/compare/v0.8.0...v0.9.0) (2026-08-11)


### Features

* parse SecretRefs, and check every ref in the file ([#39](https://github.com/villebase/sopuli-dba/issues/39)) ([3ee6591](https://github.com/villebase/sopuli-dba/commit/3ee659179fe42603d27ab9d8db0a8abdaf672d0d))

## [0.8.0](https://github.com/villebase/sopuli-dba/compare/v0.7.0...v0.8.0) (2026-08-11)


### Features

* find and layer config files, and load them in config show ([#37](https://github.com/villebase/sopuli-dba/issues/37)) ([ce02d23](https://github.com/villebase/sopuli-dba/commit/ce02d23400c3c0a3279684a5792ffc1cd9146572))

## [0.7.0](https://github.com/villebase/sopuli-dba/compare/v0.6.0...v0.7.0) (2026-08-11)


### Features

* expand target sets into targets, with labels and overrides ([#35](https://github.com/villebase/sopuli-dba/issues/35)) ([ed80879](https://github.com/villebase/sopuli-dba/commit/ed808799378faf1646bb6e594d91b31b5613d75f))

## [0.6.0](https://github.com/villebase/sopuli-dba/compare/v0.5.0...v0.6.0) (2026-08-10)


### Features

* model policies, profiles, defaults and runtime, and resolve every name ([#32](https://github.com/villebase/sopuli-dba/issues/32)) ([449cd88](https://github.com/villebase/sopuli-dba/commit/449cd886000892972fa44f82e9132d078ed87f73))

## [0.5.0](https://github.com/villebase/sopuli-dba/compare/v0.4.0...v0.5.0) (2026-08-10)


### Features

* model and validate the estate sections ([#28](https://github.com/villebase/sopuli-dba/issues/28)) ([75844fa](https://github.com/villebase/sopuli-dba/commit/75844fa71dddaa4d0abd44e63ed2c5191ac94dce))

## [0.4.0](https://github.com/villebase/sopuli-dba/compare/v0.3.0...v0.4.0) (2026-08-10)


### Features

* model and validate the application binding ([#25](https://github.com/villebase/sopuli-dba/issues/25)) ([63f551c](https://github.com/villebase/sopuli-dba/commit/63f551c66bda2fe736dd29bb1675fd257116b1d6))

## [0.3.0](https://github.com/villebase/sopuli-dba/compare/v0.2.0...v0.3.0) (2026-08-09)


### Features

* load and validate the config file layer ([#22](https://github.com/villebase/sopuli-dba/issues/22)) ([fc776e6](https://github.com/villebase/sopuli-dba/commit/fc776e6af3dea217d1e25ca8b583dee29bab3b78))

## [0.2.0](https://github.com/villebase/sopuli-dba/compare/v0.1.1...v0.2.0) (2026-08-09)


### Features

* add --color, NO_COLOR and TTY detection to text output ([#17](https://github.com/villebase/sopuli-dba/issues/17)) ([f3a637f](https://github.com/villebase/sopuli-dba/commit/f3a637f32fc972750737075df96677729fee544e))

## [0.1.1](https://github.com/villebase/sopuli-dba/compare/v0.1.0...v0.1.1) (2026-08-09)


### Bug Fixes

* write UTF-8 to stdin, stdout and stderr regardless of redirection ([#14](https://github.com/villebase/sopuli-dba/issues/14)) ([de29d2b](https://github.com/villebase/sopuli-dba/commit/de29d2b60a5b2953ec9450ed947c5fa6382e9807))

## 0.1.0 (2026-08-09)


### Features

* bootstrap sopuli CLI skeleton ([#7](https://github.com/villebase/sopuli-dba/issues/7)) ([11374ff](https://github.com/villebase/sopuli-dba/commit/11374ff548f1d8603e025c34d995257221a4e7bb))
