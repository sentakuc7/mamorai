# 依存パッケージのライセンス一覧 / Third-party licenses

MamorAI（Wazuh 版）が実行時に使う npm パッケージ（開発用のものを除く）。package-lock.json から作成（2026-11-15）。
各パッケージのライセンス本文は、インストール後の node_modules/<パッケージ>/LICENSE を参照してください。

この一覧のほかに、インストーラーは次のものをそれぞれの配布元から取得します（MamorAI には同梱しません）: Wazuh（GPLv2、packages.wazuh.com）、Docker Engine、Node.js のコンテナイメージ（node:22-alpine）、Sysmon（Microsoft Sysinternals の使用許諾。download.sysinternals.com から取得）とその設定ファイル（SwiftOnSecurity/sysmon-config。GitHub から取得）、Tailscale（任意）。SCS 評価制度の評価基準（IPA の Excel）も同梱せず、利用時に IPA のサイトから取得します。

同梱データ: `web/public/countries-110m.json`（世界地図の境界。world-atlas（ISC）経由の Natural Earth のデータ（パブリックドメイン））。

| ライセンス | 件数 |
|---|---|
| MIT | 201 |
| Apache-2.0 | 31 |
| ISC | 20 |
| BSD-3-Clause | 5 |
| (MIT OR WTFPL) | 1 |
| (MIT OR GPL-3.0-or-later) | 1 |
| (MIT AND Zlib) | 1 |
| (BSD-2-Clause OR MIT OR Apache-2.0) | 1 |
| 0BSD | 1 |
| Unlicense | 1 |

| パッケージ | 版 | ライセンス | 備考 |
|---|---|---|---|
| @aws-sdk/client-ec2 | 3.1152.0 | Apache-2.0 |  |
| @aws-sdk/client-lightsail | 3.1152.0 | Apache-2.0 |  |
| @aws-sdk/core | 3.978.3 | Apache-2.0 |  |
| @aws-sdk/credential-provider-env | 3.972.74 | Apache-2.0 |  |
| @aws-sdk/credential-provider-http | 3.972.76 | Apache-2.0 |  |
| @aws-sdk/credential-provider-ini | 3.973.19 | Apache-2.0 |  |
| @aws-sdk/credential-provider-login | 3.972.81 | Apache-2.0 |  |
| @aws-sdk/credential-provider-node | 3.972.86 | Apache-2.0 |  |
| @aws-sdk/credential-provider-process | 3.972.74 | Apache-2.0 |  |
| @aws-sdk/credential-provider-sso | 3.973.18 | Apache-2.0 |  |
| @aws-sdk/credential-provider-web-identity | 3.972.80 | Apache-2.0 |  |
| @aws-sdk/middleware-sdk-ec2 | 3.972.62 | Apache-2.0 |  |
| @aws-sdk/nested-clients | 3.997.48 | Apache-2.0 |  |
| @aws-sdk/signature-v4-multi-region | 3.996.48 | Apache-2.0 |  |
| @aws-sdk/token-providers | 3.1150.0 | Apache-2.0 |  |
| @aws-sdk/types | 3.974.6 | Apache-2.0 |  |
| @aws-sdk/xml-builder | 3.972.41 | Apache-2.0 |  |
| @aws/lambda-invoke-store | 0.3.0 | Apache-2.0 |  |
| @pinojs/redact | 0.4.0 | MIT |  |
| @remix-run/router | 1.23.4 | MIT |  |
| @smithy/core | 3.36.0 | Apache-2.0 |  |
| @smithy/credential-provider-imds | 4.5.2 | Apache-2.0 |  |
| @smithy/fetch-http-handler | 5.8.0 | Apache-2.0 |  |
| @smithy/node-http-handler | 4.12.1 | Apache-2.0 |  |
| @smithy/signature-v4 | 5.7.4 | Apache-2.0 |  |
| @smithy/types | 4.19.0 | Apache-2.0 |  |
| @types/node | 18.19.130 | MIT |  |
| @zip.js/zip.js | 2.7.57 | BSD-3-Clause |  |
| accepts | 2.0.0 | MIT |  |
| agent-base | 7.1.4 | MIT |  |
| ansi-regex | 5.0.1 | MIT |  |
| ansi-styles | 4.3.0 | MIT |  |
| asn1 | 0.2.6 | MIT |  |
| atomic-sleep | 1.0.0 | MIT |  |
| base64-js | 1.5.1 | MIT |  |
| bcrypt-pbkdf | 1.0.2 | BSD-3-Clause |  |
| better-sqlite3 | 12.11.1 | MIT |  |
| bignumber.js | 9.3.1 | MIT |  |
| bindings | 1.5.0 | MIT |  |
| bl | 4.1.0 | MIT |  |
| body-parser | 2.4.0 | MIT |  |
| bowser | 2.14.1 | MIT |  |
| buffer | 5.7.1 | MIT |  |
| buffer-equal-constant-time | 1.0.1 | BSD-3-Clause |  |
| buildcheck | 0.0.7 | MIT（package.json の licenses 欄） | optional |
| bytes | 3.1.2 | MIT |  |
| call-bind-apply-helpers | 1.0.2 | MIT |  |
| call-bound | 1.0.4 | MIT |  |
| camelcase | 5.3.1 | MIT |  |
| chownr | 1.1.4 | ISC |  |
| cliui | 6.0.0 | ISC |  |
| color-convert | 2.0.1 | MIT |  |
| color-name | 1.1.4 | MIT |  |
| colorette | 2.0.19 | MIT |  |
| commander | 10.0.1 | MIT |  |
| commander | 2.20.3 | MIT |  |
| content-disposition | 2.0.1 | MIT |  |
| content-type | 2.1.0 | MIT |  |
| cookie | 0.7.2 | MIT |  |
| cookie-parser | 1.4.7 | MIT |  |
| cookie-signature | 1.0.6 | MIT |  |
| cookie-signature | 1.2.2 | MIT |  |
| core-util-is | 1.0.3 | MIT |  |
| cpu-features | 0.0.10 | MIT（package.json の licenses 欄） | optional |
| data-uri-to-buffer | 4.0.1 | MIT |  |
| debug | 4.3.4 | MIT |  |
| debug | 4.4.3 | MIT |  |
| decamelize | 1.2.0 | MIT |  |
| decompress-response | 6.0.0 | MIT |  |
| deep-extend | 0.6.0 | MIT |  |
| depd | 2.0.0 | MIT |  |
| detect-libc | 2.1.2 | Apache-2.0 |  |
| dijkstrajs | 1.0.3 | MIT |  |
| dunder-proto | 1.0.1 | MIT |  |
| ecdsa-sig-formatter | 1.0.11 | Apache-2.0 |  |
| ee-first | 1.1.1 | MIT |  |
| emoji-regex | 8.0.0 | MIT |  |
| encodeurl | 2.0.0 | MIT |  |
| end-of-stream | 1.4.5 | MIT |  |
| es-define-property | 1.0.1 | MIT |  |
| es-errors | 1.3.0 | MIT |  |
| es-object-atoms | 1.1.2 | MIT |  |
| escalade | 3.2.0 | MIT |  |
| escape-html | 1.0.3 | MIT |  |
| esm | 3.2.25 | MIT |  |
| etag | 1.8.1 | MIT |  |
| expand-template | 2.0.3 | (MIT OR WTFPL) |  |
| express | 5.3.0 | MIT |  |
| extend | 3.0.2 | MIT |  |
| fetch-blob | 3.2.0 | MIT |  |
| file-uri-to-path | 1.0.0 | MIT |  |
| finalhandler | 2.1.1 | MIT |  |
| find-up | 4.1.0 | MIT |  |
| flag-icons | 7.2.3 | MIT |  |
| formdata-polyfill | 4.0.10 | MIT |  |
| forwarded | 0.2.0 | MIT |  |
| fresh | 2.0.0 | MIT |  |
| fs-constants | 1.0.0 | MIT |  |
| function-bind | 1.1.2 | MIT |  |
| gaxios | 8.3.1 | Apache-2.0 |  |
| gcp-metadata | 9.2.1 | Apache-2.0 |  |
| get-caller-file | 2.0.5 | ISC |  |
| get-intrinsic | 1.3.0 | MIT |  |
| get-package-type | 0.1.0 | MIT |  |
| get-proto | 1.0.1 | MIT |  |
| getopts | 2.3.0 | MIT |  |
| github-from-package | 0.0.0 | MIT |  |
| google-auth-library | 11.3.1 | Apache-2.0 |  |
| google-logging-utils | 2.1.0 | Apache-2.0 |  |
| gopd | 1.2.0 | MIT |  |
| has-symbols | 1.1.0 | MIT |  |
| hasown | 2.0.4 | MIT |  |
| http-errors | 2.0.1 | MIT |  |
| https | 1.0.0 | ISC |  |
| https-proxy-agent | 7.0.6 | MIT |  |
| iconv-lite | 0.7.3 | MIT |  |
| ieee754 | 1.2.1 | BSD-3-Clause |  |
| image-size | 1.2.1 | MIT |  |
| immediate | 3.0.6 | MIT |  |
| inherits | 2.0.4 | ISC |  |
| ini | 1.3.8 | ISC |  |
| interpret | 2.2.0 | MIT |  |
| ipaddr.js | 1.9.1 | MIT |  |
| is-core-module | 2.17.0 | MIT |  |
| is-fullwidth-code-point | 3.0.0 | MIT |  |
| is-promise | 4.0.0 | MIT |  |
| isarray | 1.0.0 | MIT |  |
| js-tokens | 4.0.0 | MIT |  |
| json-bigint | 1.0.0 | MIT |  |
| jszip | 3.10.2 | (MIT OR GPL-3.0-or-later) |  |
| jwa | 2.0.1 | MIT |  |
| jws | 4.0.1 | MIT |  |
| knex | 3.3.0 | MIT |  |
| lie | 3.3.0 | MIT |  |
| locate-path | 5.0.0 | MIT |  |
| lodash | 4.18.1 | MIT |  |
| loose-envify | 1.4.0 | MIT |  |
| math-intrinsics | 1.1.0 | MIT |  |
| media-typer | 1.1.1 | MIT |  |
| merge-descriptors | 2.0.0 | MIT |  |
| mime-db | 1.54.0 | MIT |  |
| mime-types | 3.0.2 | MIT |  |
| mimic-response | 3.1.0 | MIT |  |
| minimist | 1.2.8 | MIT |  |
| mkdirp-classic | 0.5.3 | MIT |  |
| ms | 2.1.2 | MIT |  |
| ms | 2.1.3 | MIT |  |
| nan | 2.29.0 | MIT | optional |
| napi-build-utils | 2.0.0 | MIT |  |
| negotiator | 1.1.0 | MIT |  |
| node-abi | 3.99.0 | MIT |  |
| node-domexception | 1.0.0 | MIT |  |
| node-fetch | 3.3.2 | MIT |  |
| object-inspect | 1.13.4 | MIT |  |
| on-exit-leak-free | 2.1.2 | MIT |  |
| on-finished | 2.4.1 | MIT |  |
| once | 1.4.0 | ISC |  |
| p-limit | 2.3.0 | MIT |  |
| p-locate | 4.1.0 | MIT |  |
| p-try | 2.2.0 | MIT |  |
| pako | 1.0.11 | (MIT AND Zlib) |  |
| parseurl | 1.3.3 | MIT |  |
| path-exists | 4.0.0 | MIT |  |
| path-parse | 1.0.7 | MIT |  |
| path-to-regexp | 8.4.2 | MIT |  |
| pg | 8.23.1 | MIT |  |
| pg-cloudflare | 1.4.1 | MIT | optional |
| pg-connection-string | 2.14.1 | MIT |  |
| pg-connection-string | 2.6.2 | MIT |  |
| pg-int8 | 1.0.1 | ISC |  |
| pg-pool | 3.14.0 | MIT |  |
| pg-protocol | 1.16.1 | MIT |  |
| pg-types | 2.2.0 | MIT |  |
| pgpass | 1.0.5 | MIT |  |
| pino | 9.14.0 | MIT |  |
| pino-abstract-transport | 2.0.0 | MIT |  |
| pino-std-serializers | 7.1.0 | MIT |  |
| pngjs | 5.0.0 | MIT |  |
| postgres-array | 2.0.0 | MIT |  |
| postgres-bytea | 1.0.1 | MIT |  |
| postgres-date | 1.0.7 | MIT |  |
| postgres-interval | 1.2.0 | MIT |  |
| pptxgenjs | 3.12.0 | MIT |  |
| prebuild-install | 7.1.3 | MIT |  |
| process-nextick-args | 2.0.1 | MIT |  |
| process-warning | 5.1.1 | MIT |  |
| proxy-addr | 2.0.8 | MIT |  |
| pump | 3.0.4 | MIT |  |
| qrcode | 1.5.4 | MIT |  |
| qs | 6.16.1 | BSD-3-Clause |  |
| queue | 6.0.2 | MIT |  |
| quick-format-unescaped | 4.0.4 | MIT |  |
| range-parser | 1.3.0 | MIT |  |
| raw-body | 3.0.2 | MIT |  |
| rc | 1.2.8 | (BSD-2-Clause OR MIT OR Apache-2.0) |  |
| react | 18.3.1 | MIT |  |
| react-dom | 18.3.1 | MIT |  |
| react-router | 6.30.6 | MIT |  |
| react-router-dom | 6.30.6 | MIT |  |
| readable-stream | 2.3.8 | MIT |  |
| readable-stream | 3.6.2 | MIT |  |
| real-require | 0.2.0 | MIT |  |
| rechoir | 0.8.0 | MIT |  |
| require-directory | 2.1.1 | MIT |  |
| require-main-filename | 2.0.0 | ISC |  |
| resolve | 1.22.13 | MIT |  |
| resolve-from | 5.0.0 | MIT |  |
| router | 2.2.0 | MIT |  |
| safe-buffer | 5.1.2 | MIT |  |
| safe-buffer | 5.2.1 | MIT |  |
| safe-stable-stringify | 2.5.0 | MIT |  |
| safer-buffer | 2.1.2 | MIT |  |
| scheduler | 0.23.2 | MIT |  |
| semver | 7.8.5 | ISC |  |
| send | 1.2.1 | MIT |  |
| serve-static | 2.2.1 | MIT |  |
| set-blocking | 2.0.0 | ISC |  |
| setimmediate | 1.0.5 | MIT |  |
| setprototypeof | 1.2.0 | ISC |  |
| side-channel | 1.1.1 | MIT |  |
| side-channel-list | 1.0.1 | MIT |  |
| side-channel-map | 1.0.1 | MIT |  |
| side-channel-weakmap | 1.0.2 | MIT |  |
| simple-concat | 1.0.1 | MIT |  |
| simple-get | 4.0.1 | MIT |  |
| sonic-boom | 4.2.1 | MIT |  |
| split2 | 4.2.0 | ISC |  |
| ssh2 | 1.17.0 | MIT（package.json の licenses 欄） |  |
| statuses | 2.0.2 | MIT |  |
| string-width | 4.2.3 | MIT |  |
| string_decoder | 1.1.1 | MIT |  |
| string_decoder | 1.3.0 | MIT |  |
| strip-ansi | 6.0.1 | MIT |  |
| strip-json-comments | 2.0.1 | MIT |  |
| supports-preserve-symlinks-flag | 1.0.0 | MIT |  |
| tar-fs | 2.1.5 | MIT |  |
| tar-stream | 2.2.0 | MIT |  |
| tarn | 3.1.2 | MIT |  |
| thread-stream | 3.2.0 | MIT |  |
| three | 0.160.1 | MIT |  |
| tildify | 2.0.0 | MIT |  |
| toidentifier | 1.0.1 | MIT |  |
| topojson-client | 3.1.0 | ISC |  |
| tslib | 2.8.1 | 0BSD |  |
| tunnel-agent | 0.6.0 | Apache-2.0 |  |
| tweetnacl | 0.14.5 | Unlicense |  |
| type-is | 2.1.0 | MIT |  |
| undici | 7.30.1 | MIT |  |
| undici-types | 5.26.5 | MIT |  |
| unpipe | 1.0.0 | MIT |  |
| util-deprecate | 1.0.2 | MIT |  |
| vary | 1.1.2 | MIT |  |
| web-streams-polyfill | 3.3.3 | MIT |  |
| which-module | 2.0.1 | ISC |  |
| world-atlas | 2.0.2 | ISC |  |
| wrap-ansi | 6.2.0 | MIT |  |
| wrappy | 1.0.2 | ISC |  |
| xtend | 4.0.2 | MIT |  |
| y18n | 4.0.3 | ISC |  |
| yaml | 2.9.1 | ISC |  |
| yargs | 15.4.1 | MIT |  |
| yargs-parser | 18.1.3 | ISC |  |
| zod | 3.25.76 | MIT |  |
