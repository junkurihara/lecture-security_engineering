#!/usr/bin/env node

import {postMyData, getMyData} from './common/post-get';
import pgm from 'commander';


pgm.version('0.0.1');

/// for post
pgm
  .command('post <data>', '')
  .description('Post data to json-server')
  .option('-e, --encrypt', 'Encrypt with string key')
  .option('-k, --key <key>', 'String key for encryption')
  .option('-r, --remote', 'Register to remote server (zettant.com)')
  .option('-u, --universal', 'Use universal crypto library (jscu)')
  .action(async (data, options) => {
    if(options.encrypt && !options.key) {
      console.error('String key required for encryption');
      process.exit(1);
    }
    if(options.encrypt){
      console.log(`Register encrypted data to ${(options.remote)? 'remote':'local'} server`);
      console.log(`Data: ${data}`);
      console.log(`Key: ${options.key}`);
      const res = await postMyData({
        data,
        key: options.key,
        encrypt: true,
        remote: options.remote,
        universal: options.universal
      });
      console.log(`Registered id: ${res.id}`);
    }
    else {
      console.log(`Register plaintext data to ${(options.remote)? 'remote':'local'} server`);
      console.log(`Data: ${data}`);
      const res = await postMyData({
        data,
        encrypt: false,
        remote: options.remote
      });
      console.log(`Registered id: ${res.id}`);
    }
  });

/// for get
pgm
  .command('get <id>', '')
  .description('Get data from json-server')
  .option('-d, --decrypt', 'Decrypt with string key')
  .option('-k, --key <key>', 'String key for decryption')
  .option('-r, --remote', 'Retrieve from remote server (zettant.com)')
  .option('-u, --universal', 'Use universal crypto library (jscu)')
  .action(async (id, options) => {
    if(options.decrypt && !options.key) {
      console.error('String key required for decryption');
      process.exit(1);
    }
    if(options.decrypt){
      console.log(`Retrieve encrypted data to ${(options.remote)? 'remote':'local'} server`);
      console.log(`Id: ${id}`);
      console.log(`Key: ${options.key}`);
      const res = await getMyData({
        id,
        key: options.key,
        decrypt: options.decrypt,
        remote: options.remote,
        universal: options.universal
      });
      console.log(`Decrypted data: ${res.data}`);
    }
    else {
      console.log(`Retrieve plaintext data to ${(options.remote)? 'remote':'local'} server`);
      console.log(`Registered Id: ${id}`);
      const res = await getMyData({
        id,
        decrypt: false,
        remote: options.remote,
      });
      console.log(`Retrieved data: ${res.data}`);
    }
  });

pgm.parse(process.argv);
