# Changelog

Here you can see an overview of changes between each release.

## Version 4.1.0_01

Released on March 5th, 2020.

* Conformed to Gluu Server v4.1.
* Removed obsolete config and secret that previously used to automate Couchbase container.

## Version 4.0.1_09

Released on March 2nd, 2020.

* Pre-populated Passport RS cert alias.

## Version 4.0.1_08

Released on January 29th, 2020.

* Fixed hardcoded keystore password for oxTrust API.

## Version 4.0.1_07

Released on January 22nd, 2020.

* Upgraded `oxauth-client` to v4.0.Final.patch1 build at 2020-01-20.
* Added more supported keys algorithms.

## Version 4.0.1_06

Released on December 27th, 2019.

* Added credentials for SCIM test client.

## Version 4.0.1_05

Released on December 1st, 2019.

* Upgraded `oxauth-client` v4.0.1.Final build at 2019-11-30.

## Version 4.0.1_04

Released on November 19th, 2019.

* Upgraded `oxauth-client` v4.0.1.Final build at 2019-11-18.

## Version 4.0.1_03

Released on November 15th, 2019.

* Upgraded `oxauth-client` package.

## Version 4.0.1_02

Released on November 14th, 2019.

* Upgraded `pygluu-containerlib` to show connection issue with Couchbase explicitly.

## Version 4.0.1_01

Released on November 1st, 2019.

* Upgraded to Gluu Server 4.0.1.

## Version 4.0.0_01

Released on October 22nd, 2019.

* Upgraded to Gluu Server 4.0.
* Removed templates and static files to generate context for initial data.

## Version 3.1.6_02

Released on May 10th, 2019.

* Alpine upgraded to v3.9. Ref: https://github.com/GluuFederation/gluu-docker/issues/71.

## Version 3.1.6_01

Released on April 29th, 2019.

* Upgraded to Gluu Server 3.1.6.

## Version 3.1.5_05

Released on May 10th, 2019.

* Alpine upgraded to v3.9. Ref: https://github.com/GluuFederation/gluu-docker/issues/71.

## Version 3.1.5_04

Released on April 23rd, 2019.

* Changed default expiration time for oxAuth keys.

## Version 3.1.5_03

Released on April 9th, 2019.

* Added license info on container startup.
* Added new command `migrate` to migrate some keys from config to secret backend.

## Version 3.1.5_02

Released on March 28th, 2019.

* Added `wait_for` in `load` and `dump` commands.

## Version 3.1.5_01

Released on March 23rd, 2019.

* Upgraded to Gluu Server 3.1.5.

## Version 3.1.4_04

Released on April 4th, 2019.

* Added license info during container run.

## Version 3.1.4_03

Released on December 2nd, 2018.

* Removed Casa scripts from distribution.

## Version 3.1.4_02

Released on November 28th, 2018.

* Fixed issue with single-quotation when generating certificate.

## Version 3.1.4_01

Released on November 12th, 2018.

* Upgraded to Gluu Server 3.1.4.

## Version 3.1.3_06

Released on September 18th, 2018.

* Changed base image to use Alpine 3.8.1.

## Version 3.1.3_05

Released on September 12th, 2018.

* Added feature to connect to secure Consul (HTTPS).

## Version 3.1.3_04

Released on September 6th, 2018.

* Added feature to guard existing keys being overwritten when executing `generate` and `load` commands.
* Added environment variable to force rewrite all keys when executing `generate` and `load` commands.

## Version 3.1.3_03

Released on August 3rd, 2018.

* Added optional params for baseInum, inumOrg, and inumAppliance.

## Version 3.1.3_02

Released on July 19th, 2018.

* Added wrapper to manage config via Consul KV or Kubernetes configmap.
* Added feature to dump config into JSON file when running `generate` command.

## Version 3.1.3_01

Released on June 6th, 2018.

* Upgraded to Gluu Server 3.1.3.

## Version 3.1.2_01

Released on June 6th, 2018.

* Upgraded to Gluu Server 3.1.2.

## Version 3.1.1_rev1.0.0-beta3

Released on October 25th, 2017.

* Fixed work_phone dynamic script.

## Version 3.1.1_rev1.0.0-beta2

Released on October 11th, 2017.

* Added default person OC.

## Version 3.1.1_rev1.0.0-beta1

Released on October 6th, 2017.

* Migrated to Gluu Server 3.1.1.

## Version 3.0.1_rev1.0.0-beta6

Released on September 29th, 2017.

* Added feature to use existing `oxauth-keys.jks` file (for migrating external LDAP/CE version).

## Version 3.0.1_rev1.0.0-beta5

Released on September 19th, 2017.

* Added options to input external encoded salt, ox LDAP password, and inum appliance (for migrating external LDAP/CE version).

## Version 3.0.1_rev1.0.0-beta4

Released on August 23rd, 2017.

* Added patches to prevent accidentally updating keys when entrypoint is re-executed.

## Version 3.0.1_rev1.0.0-beta3

Released on July 20th, 2017.

* Added config to store first instance of LDAP

## Version 3.0.1_rev1.0.0-beta2

Released on July 8th, 2017.

* Added feature to generate self-signed SSL cert and key if not exist yet. These cert and key can be overriden by mapping volumes.

## Version 3.0.1_rev1.0.0-beta1

Released on July 7th, 2017.

* Added feature to generate global config and save it to Consul.
