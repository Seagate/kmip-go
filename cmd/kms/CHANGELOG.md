# [1.2.0] (2022-10-10)

### Features

- Added new command `banner title=value` to print a single word banner.
  - Example:
    - `banner title=PyKMIP`
  - Output:
    - ============================== PyKMIP ==============================
- Added new command `set elapsed=true|false` which displays command elapsed time when true
- Added new command `clear id=value` which will locate, revoke, and destroy a key based on an id
- Added new variable concept, with one new variable `${lastuid}` which is set after a Create or Locate call. 
- Example script using last uid variable:
  - `load file=kms-pykmip.json`
  - `open`
  - `create id=DISKSM0123456789`
  - `activate uid=${lastuid}`
  - `get uid=${lastuid}`
  - `locate id=DISKSM0123456789`
  - `revoke uid=${lastuid}`
  - `destroy uid=${lastuid}`
  - `close`

# [1.1.2] (2022-09-13)

### Chore

- Move common package files under the src/kmipapi package

# [1.1.1] (2022-09-12)

### Fix

- Locate Request/Response corrections for KMIP 1.4
- README corrections

# [1.1.0] (2022-09-12)

### Features

- Added `query op=[1|3]` to query a KMS server, both KMIP 1.4 and 2.0 working
- Added `discover [major=<value> minor=<value>]` to discover versions supported by a server

# [1.0.0] (2022-09-18)

### Features

- First release
- Support for KMIP 1.4 and 2.0 versions
- Variable configuration settings
- Loading and storing json-file-based configuration settings
- Executing open and close KMS server sessions
- Executing create, activate, get, locate, revoke, and destroy key operations
- Running a script file
- Dynamic multi-level logging
