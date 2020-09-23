/**
 * Get jscu
 */
export const getJscu = () => {
  let jscu;
  const global = Function('return this;')();
  if (typeof window !== 'undefined'){
    jscu = window.jscu;
  }
  else{
    jscu = require('js-crypto-utils');
    global.jscu = jscu;
  }

  return jscu;
};

/**
 * Get fetch
 */
export const getFetch = () => {
  // node-fetch in aws sdk
  let fetch;
  const global = Function('return this;')();
  if (typeof window === 'undefined'){
    fetch = require('node-fetch');
    global.fetch = fetch;
  }
  else {
    fetch = window.fetch;
  }
  return fetch;
};

