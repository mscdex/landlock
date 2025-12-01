'use strict';

const assert = require('assert');
const { openSync, readdirSync } = require('fs');

const landlock = require('..');
const { constants } = landlock;

const getFDCount = () => readdirSync(`/proc/${process.pid}/fd`).length;

assert(
  typeof landlock.constants === 'object'
    && landlock.constants !== null
    && Object.keys(landlock.constants).length > 0
);

{
  const abi = landlock.getABI();
  assert(Number.isInteger(abi) && abi > 0);
  console.log(`Landlock ABI version ${abi}`);
}

{
  const beforeFDCount = getFDCount();
  const fd = landlock.createRuleset(
    constants.LANDLOCK_ACCESS_FS_READ_FILE
  );
  assert.strictEqual(getFDCount(), beforeFDCount + 1);
  landlock.setNoNewPrivs();
  landlock.restrictSelf(fd);
  landlock.close(fd);
  assert.strictEqual(getFDCount(), beforeFDCount);

  assert.throws(
    () => openSync(__filename, 'r'),
    { syscall: 'open', code: 'EACCES' }
  );
}
