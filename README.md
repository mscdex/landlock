# Description

A binding to Linux's [Landlock](https://docs.kernel.org/userspace-api/landlock.html) security module for [node.js](https://nodejs.org).

Supports Landlock ABI versions 1-7.

Information on feature availability per ABI version can be found [here](https://docs.kernel.org/userspace-api/landlock.html#previous-limitations).

# Requirements

* Linux kernel v5.13+
  * `CONFIG_SECURITY_LANDLOCK=y`
  * One or both of:
    * `CONFIG_LSM` contains the value: `landlock`
    * The kernel command line parameter `lsm` contains the value: `landlock`
* [node.js](http://nodejs.org/) -- v10.x or newer
* An appropriate build environment -- see [node-gyp's documentation](https://github.com/nodejs/node-gyp/blob/main/README.md)

# Installation

    npm install landlock

# Examples

* Disallow reading or writing of any file (note: files can still be created if
  the filesystem allows, but they will not be able to be written to)
```js
const fs = require('fs');

const landlock = require('landlock');

const fd = landlock.createRuleset(
  landlock.constants.LANDLOCK_ACCESS_FS_READ_FILE
    | landlock.constants.LANDLOCK_ACCESS_FS_WRITE_FILE
    | landlock.constants.LANDLOCK_ACCESS_FS_TRUNCATE_FILE
);
landlock.setNoNewPrivs();
landlock.restrictSelf(fd);
landlock.close(fd);

// Throws
fs.readFileSync(__filename);

// Throws, but creates a zero-length file
fs.writeFileSync('test.txt', 'foo');
```

* Disallow execution of any file outside of /usr/bin
```js
const { execFileSync } = require('child_process');

const landlock = require('landlock');

const fd = landlock.createRuleset(
  landlock.constants.LANDLOCK_ACCESS_FS_EXECUTE
);
landlock.addRule(
  fd,
  landlock.constants.LANDLOCK_RULE_PATH_BENEATH,
  landlock.constants.LANDLOCK_ACCESS_FS_EXECUTE,
  '/usr/bin'
);
landlock.setNoNewPrivs();
landlock.restrictSelf(fd);
landlock.close(fd);

// Throws
console.log(
  execFileSync('/usr/local/bin/node', [ '-v' ], { encoding: 'utf8' })
);
```

# API

## Exports

* **addRule**(< _integer_ >fd, < _mixed_ >ruleType[, ...ruleTypeArgs]) - _(void)_ - 
  Adds a new rule to a ruleset. `ruleType` can be an _integer_ or _bigint_.
  `...ruleTypeArgs` depends on `ruleType`:

    * `LANDLOCK_RULE_PATH_BENEATH`: < _mixed_ >allowedAccess, < _mixed_ >parent -
      `allowedAccess` is an _integer_ or _bigint_ bitmask of allowed actions for
      this file hierarchy. `parent` is either a _string_ path or a _integer_
      file descriptor which identifies the parent directory of a file hierarchy,
      or just a file.

    * `LANDLOCK_RULE_NET_PORT`: < _integer_ >allowedAccess, < _integer_ >port -
      `allowedAccess` is an _integer_ or _bigint_ bitmask of allowed actions for
      this file hierarchy. `port` is a network port.

* **close**(< _integer_ >fd) - _(void)_ - Closes the given file descriptor.

* **constants** - _object_ - Contains useful Landlock constants, all named the
  same as the original C macros. All values are of type _bigint_.

* **createRuleset**(< _mixed_ >fsAccess[, < _mixed_ >netAccess[, < _mixed_ >scoped]]) - _integer_ -
  Creates a new ruleset and returns the resulting file descriptor. All values
  can be either an _integer_ or _bigint_.

* **getABI**() - _integer_ - Returns the highest supported Landlock ABI version
  (starting at 1).

* **getErrata**() - _bigint_ - Returns a bitmask of fixed issues for the current
  Landlock ABI version.

* **restrictSelf**(< _integer_ >fd[, < _mixed_ >flags]) - _(void)_ - Enforce a
  ruleset on the calling thread. `flags` can be an _integer_ or _bigint_.

* **setNoNewPrivs**() - _(void)_ - Enables no_new_privs mode.
