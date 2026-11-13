'use strict';
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');

async function start() {
  process.env.MONGOMS_VERSION = process.env.MONGOMS_VERSION || '7.0.24';
  if (process.env.MONGOD_BINARY) process.env.MONGOMS_SYSTEM_BINARY = process.env.MONGOD_BINARY;
  const mongo = await MongoMemoryServer.create({ instance: { launchTimeout: 60000 } });
  process.env.MONGODB_URI = mongo.getUri('passport-baseline');
  process.env.PORT = process.env.PORT || '3007';
  await mongoose.connect(process.env.MONGODB_URI);
  require('../app');
  console.log('Local app: http://localhost:' + process.env.PORT);
  console.log('Temporary database: accounts disappear after shutdown.');
  async function stop() {
    await mongoose.disconnect();
    await mongo.stop();
    process.exit(0);
  }
  process.on('message', message => { if (message === 'stop') stop(); });
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}
start().catch(error => { console.error(error); process.exit(1); });
