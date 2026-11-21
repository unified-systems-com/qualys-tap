# Changelog

## [0.1.1](https://github.com/unified-systems-com/qualys-tap/compare/v0.1.0...v0.1.1) (2026-11-21)


### Features

* **collector:** the live Qualys collector ([0115f40](https://github.com/unified-systems-com/qualys-tap/commit/0115f40ca91ea1c59b3133ecc57c9c9a9cd54271))
* **collector:** the live Qualys collector ([6d54475](https://github.com/unified-systems-com/qualys-tap/commit/6d54475cc1669f5f9e30c89240fe1f5b4e68afd9))
* **contract:** JSON Schemas for consumed.json and extract.json ([6e9a584](https://github.com/unified-systems-com/qualys-tap/commit/6e9a584e51210155e0739b8e5713cf5a9c385ba8))
* **credential:** the qualys_api_credential envelope ([7917a9a](https://github.com/unified-systems-com/qualys-tap/commit/7917a9af362622ce242c06c37f51c57fa317a232))
* **credential:** the qualys_api_credential envelope ([0b548d7](https://github.com/unified-systems-com/qualys-tap/commit/0b548d73663452e29dfc917ea6fa37167339584e))
* **ec2:** link a Qualys host to the EC2 instance aws_core holds ([e04f3de](https://github.com/unified-systems-com/qualys-tap/commit/e04f3de09cc5147f8cdae234b5df01abb9b75e8a))
* **ec2:** link a Qualys host to the EC2 instance aws_core holds ([a2d9e50](https://github.com/unified-systems-com/qualys-tap/commit/a2d9e500bbd9d821dccd11066c572197adc50463))
* **neutral:** the neutral finding, the shared vulnerability record and the package link ([6c86783](https://github.com/unified-systems-com/qualys-tap/commit/6c86783f882f07eb6c5ce32746202ff82a2af1ef))
* **neutral:** the neutral finding, the shared vulnerability record and the package link ([5cc6921](https://github.com/unified-systems-com/qualys-tap/commit/5cc6921f11d6381b363e0935b169e59eccb70d26))
* parsed pages into grid nodes and edges, with Qualys-only resolution ([e1c33d5](https://github.com/unified-systems-com/qualys-tap/commit/e1c33d5e25673c16077a03e63ab4a12a29f91b6a))
* parsed pages into grid nodes and edges, with Qualys-only resolution ([9026ed2](https://github.com/unified-systems-com/qualys-tap/commit/9026ed28526c962a263db14a5340cd464020af17))
* **parsers:** the parser registry and the package-table parser ([f256e2b](https://github.com/unified-systems-com/qualys-tap/commit/f256e2be1de115bfc5697fd4836d4b92b811e7e3))
* **parsers:** the parser registry and the package-table parser ([3208baf](https://github.com/unified-systems-com/qualys-tap/commit/3208bafdc38234395fa96758006a55ac20eaf4e9))
* qualys_load, the export-archive loader ([d3545c5](https://github.com/unified-systems-com/qualys-tap/commit/d3545c5d25a06025ffb63503d050f20054ce9e5b))
* qualys_load, the export-archive loader ([a716883](https://github.com/unified-systems-com/qualys-tap/commit/a7168831cd0cdccba1bea5809aeb2219f204184c))
* the DTD contract extract and the page parser ([5835c7a](https://github.com/unified-systems-com/qualys-tap/commit/5835c7aa676e4e27a89acf325820c8cda26a5dc8))
* the DTD contract extract and the page parser ([e320dea](https://github.com/unified-systems-com/qualys-tap/commit/e320dea390719df13e963324f1432bf12a0f029b))
* the read-only transport ([45d1104](https://github.com/unified-systems-com/qualys-tap/commit/45d1104d860169a511793e59cea1c339066921be))
* the read-only transport ([3283710](https://github.com/unified-systems-com/qualys-tap/commit/328371051c41eed386e2c256f3ceab3dd6030b5c))


### Bug Fixes

* **archive:** one snapshot for hash and load; keep only read members; refuse bad qids.txt ([bdfd6d9](https://github.com/unified-systems-com/qualys-tap/commit/bdfd6d9d368d06f0d460e5f235cd788a4f5245fe))
* **client:** a non-finite wait header falls back to the default wait ([b04ab10](https://github.com/unified-systems-com/qualys-tap/commit/b04ab107acaac25785e82813b52e77f98d137a00))
* **client:** refuse any request body; serialise reads ([87a2ccc](https://github.com/unified-systems-com/qualys-tap/commit/87a2ccc1bb5521eef9bf9dfed71e7e4b8c188ed8))
* **client:** stateless sessions: no cookie kept, sent or accepted ([5ad3be4](https://github.com/unified-systems-com/qualys-tap/commit/5ad3be4dda933f061f7aa50d013705d1e273587c))
* **collector:** a cut knowledge-base page that moves nothing forward is incomplete ([eca28bd](https://github.com/unified-systems-com/qualys-tap/commit/eca28bd83598eb18a3bc8af6c8efebaec40afcfc))
* **collector:** fixed probe-failure messages; refused envelopes proven leak-free ([090dcc9](https://github.com/unified-systems-com/qualys-tap/commit/090dcc98cd86e00888b26d4dd850b66715b5b41c))
* **collector:** rebuild every page request; isolate a failing subscription ([86f0243](https://github.com/unified-systems-com/qualys-tap/commit/86f02431acf8051bee1636cf099b30fa96adabed))
* **credential:** a wrong scope or kind echoes nothing from the envelope ([25ca42c](https://github.com/unified-systems-com/qualys-tap/commit/25ca42ceab717205ff745bfe20c6dc4271209845))
* **credential:** an unreadable envelope is reported, never read as absent ([b1edd50](https://github.com/unified-systems-com/qualys-tap/commit/b1edd505f6069a24e1139ddfcb650b81b66f4982))
* **credential:** the standing scope cannot be changed after validation ([b41a9ed](https://github.com/unified-systems-com/qualys-tap/commit/b41a9eda3af4d2f2fb806ff8f1687fb324bbd6fd))
* **decompose:** close the remaining ways a complete label could withdraw wrongly ([a23b514](https://github.com/unified-systems-com/qualys-tap/commit/a23b5149090e45141be4f33b0bb46cc408cc7fe8))
* **decompose:** guard the complete label, record completeness honestly, list drops ([f7a8151](https://github.com/unified-systems-com/qualys-tap/commit/f7a8151679b38fce4be80555df68882ad9dff48e))
* **decompose:** no complete read without a read time ([23f796f](https://github.com/unified-systems-com/qualys-tap/commit/23f796f830597e8e73bb77e2ca76986b207af298))
* **decompose:** the batch description names the kind the run was treated as ([63cbc28](https://github.com/unified-systems-com/qualys-tap/commit/63cbc28464a0767211f0a096c8465e406e2f22ec))
* **ec2:** count only deprecated-field-only hosts as unresolved ([60419d5](https://github.com/unified-systems-com/qualys-tap/commit/60419d593ad2a5a8083cf9b1d9e516ed80083dcb))
* **load:** every page's time is checked against the future bound ([619bafe](https://github.com/unified-systems-com/qualys-tap/commit/619bafe9ff14ee4e8b31ab7b789486ad5a393871))
* **load:** serialise loads per subscription; refuse duplicate member names ([72f8025](https://github.com/unified-systems-com/qualys-tap/commit/72f80251e7c0fd972aa2db4048525fe5c5bd87cb))
* **neutral:** a host with a QID of unknown CVEs claims partial ([cf71273](https://github.com/unified-systems-com/qualys-tap/commit/cf71273133855d1952a8ff477326c281054eb844))
* **neutral:** never resolve on unknown QIDs; required versions independent of order ([dcafac9](https://github.com/unified-systems-com/qualys-tap/commit/dcafac9a4fe57c11cd46257424cf89cd4dab612e))
* **neutral:** no fixed version on disagreement; over-long package keys never sent ([082243e](https://github.com/unified-systems-com/qualys-tap/commit/082243e04e5608df9ab3d65402c5f6bb39a2fb2d))
* **neutral:** partial claims on a partly read run; scope and order the shared records ([3237582](https://github.com/unified-systems-com/qualys-tap/commit/3237582de60ade6ad18967a762bddb59c4a6e735))
* **parse:** enforce required attributes and nested required groups ([9f9354a](https://github.com/unified-systems-com/qualys-tap/commit/9f9354a1a930371fa0decfb900cc331fa83bec69))
* **parse:** refuse a repeated once-only child; bound entity nesting ([abc8b01](https://github.com/unified-systems-com/qualys-tap/commit/abc8b012c96557f18bbaf331dd57914ff9bd1ab7))
* **reduce:** bound parameter-entity expansion while it grows ([8c30cda](https://github.com/unified-systems-com/qualys-tap/commit/8c30cda4b784024e8cb3bfd6941623299408c075))


### Documentation

* **spec:** a matching-scope archive withdraws hosts it does not contain ([5d38654](https://github.com/unified-systems-com/qualys-tap/commit/5d3865413001bc0e4d6a4db627c55028f44593c3))
* **spec:** archive trust, scope matching and the watermark gap ([da1a5a9](https://github.com/unified-systems-com/qualys-tap/commit/da1a5a93c30b1b7e0bc099007ba6a7c6296a98d0))
* **spec:** file import and states move to In Development ([835512e](https://github.com/unified-systems-com/qualys-tap/commit/835512e4c1b73da6dc0314c2f9e607f52e87e7a7))
* **spec:** record archive trust, scope matching and the watermark gap ([93871db](https://github.com/unified-systems-com/qualys-tap/commit/93871db8aa0e6d6437ea8ee8c5cabb4d2701e68f))
* **spec:** the standing tag scope always sends tag_include_selector=any ([4c9fede](https://github.com/unified-systems-com/qualys-tap/commit/4c9fede2cf79f8945c11f1b782e0997279906418))
