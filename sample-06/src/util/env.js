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
