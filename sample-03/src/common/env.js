import fetch from 'cross-fetch';
import jscu from 'js-crypto-utils';

/**
 * Get jscu
 */
export const getJscu = () => {
  const global = Function('return this;')();
  if (typeof window !== 'undefined'){
    return window.jscu;
  }
  else{
    global.jscu = jscu;
    return jscu;
  }
};

/**
 * Get fetch
 */
export const getFetch = () => {
  // node-fetch in aws sdk
  const global = Function('return this;')();
  if (typeof window === 'undefined'){
    global.fetch = fetch;
    return fetch;
  }
  else {
    return window.fetch;
  }
};
